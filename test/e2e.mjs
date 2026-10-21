// End-to-end smoke test: loads the three policy.wasm builds and evaluates
// them through the vendored @open-policy-agent/opa-wasm browser bundle
// (the exact module the Pages playground imports). CI runs this after
// `make build`; it fails loudly if the wasm build, the vendored bundle,
// or the OPA↔wasm ABI drift apart.
//
// Usage: node test/e2e.mjs            (expects build/wasm/*.wasm)

import { readFileSync } from 'node:fs'
import opaWasm from '../site/vendor/opa-wasm-browser.esm.js'

const { loadPolicy } = opaWasm

const wasmDir = new URL('../build/wasm/', import.meta.url)

async function load(name) {
	return loadPolicy(readFileSync(new URL(`${name}.wasm`, wasmDir)))
}

function assert(condition, message) {
	if (!condition) {
		console.error(`FAIL: ${message}`)
		process.exitCode = 1
	} else {
		console.log(`ok: ${message}`)
	}
}

function hasFinding(result, rule) {
	return result.findings.some((f) => f.rule === rule)
}

const today = '2026-10-20'

const validEnclave = {
	enclave: 'checkout',
	owner: 'Checkout team',
	trustedIdentityPlanes: [
		{ plane: 'customer-web', provider: 'opaque-token' },
		{ plane: 'internal-services', provider: 'mtls-svid' },
	],
	borderInventory: ['checkout-web-tier', 'checkout-payment-redirect'],
	blastRadius: {
		data: 'Cart contents and customer profile cache',
		statedLimit: 'Cart rows for one storefront, one hour',
	},
	reviewedOn: '2026-09-15',
}

const validSeam = {
	seam: 'checkout-web-tier',
	enclave: 'checkout',
	entry: 'Internet-facing endpoint behind the edge gateway; mTLS terminates at the gateway and requests continue with a forwarded identity token',
	decision: 'Default deny at the gateway; each route is an explicit allow',
	monitoring: 'Gateway access logs, p99 latency metric, alert on 5xx rate',
	blastRadius: 'A spoofed session can read one customer cart',
	killPath: 'Drop the gateway route; the edge fails closed',
	lastRehearsed: '2026-08-30',
	reviewDate: '2026-12-01',
}

const validBundle = {
	enclaves: [
		{ ...validEnclave, borderInventory: ['checkout-web-tier'] },
		{
			enclave: 'payments',
			owner: 'Payments team',
			trustedIdentityPlanes: [{ plane: 'internal-services', provider: 'mtls-svid' }],
			borderInventory: ['payments-3ds-redirect'],
			blastRadius: {
				data: 'Charge attempts and masked card references',
				statedLimit: 'One payment provider account, 24 hours',
			},
			reviewedOn: '2026-09-02',
		},
	],
	seams: [
		validSeam,
		{
			seam: 'payments-3ds-redirect',
			enclave: 'payments',
			entry: 'Browser redirect back from the 3-D Secure provider; the callback is authenticated with a signed token tied to the original auth challenge',
			decision: 'Verify the callback signature and deny unverified callbacks',
			monitoring: 'Every callback logged and counted; alert on verification failure rate',
			blastRadius: 'A forged callback could mark a charge as completed',
			killPath: 'Disable the callback route; pending charges fail closed',
			lastRehearsed: '2026-09-10',
			reviewDate: '2026-11-15',
		},
	],
}

const enclavePolicy = await load('enclave')
const seamPolicy = await load('seam')
const crossPolicy = await load('cross')

// --- enclave -------------------------------------------------------------

let r = enclavePolicy.evaluate({ contract: validEnclave, today })[0].result
assert(r.valid === true && r.findings.length === 0, 'valid enclave contract passes in wasm')

r = enclavePolicy.evaluate({ contract: { ...validEnclave, reviewedOn: '2026-10-21' }, today })[0].result
assert(hasFinding(r, 'contract/reviewed-in-future') && r.valid === false, 'future review date is an error in wasm')

r = enclavePolicy.evaluate({ contract: { ...validEnclave, reviewedOn: '2026-02-30' }, today })[0].result
assert(hasFinding(r, 'contract/reviewed-on-invalid'), 'impossible calendar date is rejected in wasm')

r = enclavePolicy.evaluate({ contract: { ...validEnclave, reviewedOn: '2025-10-19' }, today })[0].result
assert(hasFinding(r, 'contract/reviewed-stale'), 'stale review date is an error in wasm')

r = enclavePolicy.evaluate({ contract: { ...validEnclave, trustedIdentityPlanes: [] }, today })[0].result
assert(hasFinding(r, 'contract/trusted-identity-planes-required'), 'empty identity planes is an error in wasm')

r = enclavePolicy.evaluate({ contract: { ...validEnclave, borderInventory: ['nobody-signed-this-seam', 42] }, today })[0].result
assert(hasFinding(r, 'contract/border-inventory-entry-must-be-string'), 'non-string border entry is an error in wasm')

// --- seam -----------------------------------------------------------------

r = seamPolicy.evaluate({ contract: validSeam, today })[0].result
assert(r.valid === true && r.findings.length === 0, 'valid seam contract passes in wasm')

r = seamPolicy.evaluate({ contract: { ...validSeam, decision: 'Only the storefront may call through' }, today })[0].result
assert(r.valid === true && hasFinding(r, 'contract/decision-no-deny-rule'), 'missing deny rule is a warning, not an error')

r = seamPolicy.evaluate({ contract: { ...validSeam, lastRehearsed: '2026-04-01' }, today })[0].result
assert(hasFinding(r, 'contract/last-rehearsed-stale'), 'stale rehearsal is an error in wasm')

r = seamPolicy.evaluate({ contract: { ...validSeam, reviewDate: '2026-10-19' }, today })[0].result
assert(hasFinding(r, 'contract/review-overdue'), 'overdue review date is an error in wasm')

// --- bundle ---------------------------------------------------------------

r = crossPolicy.evaluate(validBundle)[0].result
assert(r.valid === true && r.findings.length === 0, 'valid bundle passes in wasm')

r = crossPolicy.evaluate({
	enclaves: validBundle.enclaves,
	seams: [validBundle.seams[0], { ...validBundle.seams[1], enclave: 'billing' }],
})[0].result
assert(hasFinding(r, 'bundle/seam-enclave-unknown'), 'seam pointing at unknown enclave is an error in wasm')

r = crossPolicy.evaluate({
	enclaves: [{ ...validEnclave, borderInventory: ['checkout-web-tier', 'ghost-seam'] }, validBundle.enclaves[1]],
	seams: validBundle.seams,
})[0].result
assert(hasFinding(r, 'bundle/border-seam-without-contract'), 'uncovered border seam is an error in wasm')

r = crossPolicy.evaluate({ enclaves: [validEnclave, validEnclave], seams: validBundle.seams })[0].result
const dupes = r.findings.filter((f) => f.rule === 'bundle/duplicate-enclave-name')
assert(dupes.length === 1, 'duplicate enclave name reported exactly once in wasm')

console.log(process.exitCode ? 'e2e: FAILED' : 'e2e: all assertions passed')

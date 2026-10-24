// End-to-end smoke test: loads the five policy.wasm builds and evaluates
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

// A compact authorization policy set for the authz bundle. Semantics
// mirror the unit-test fixture: clerk read allow, clerk charge with
// MFA condition, admin wildcard allow, offboarded deny.
const authzPolicySet = {
	name: 'storefront',
	currentVersion: 2,
	subjects: [
		{ id: 'alice', roles: ['admin'], flags: ['mfa-verified'] },
		{ id: 'bob', roles: ['clerk'], flags: [] },
		{ id: 'carol', roles: [], flags: ['offboarded'] },
	],
	versions: [
		{
			version: 1,
			effectiveFrom: '2026-01-01',
			effectiveTo: '2026-06-30',
			rules: [
				{ id: 'clerk-read-v1', effect: 'allow', subject: { role: 'clerk' }, action: 'order.read', resource: 'orders-*' },
			],
		},
		{
			version: 2,
			effectiveFrom: '2026-07-01',
			rules: [
				{ id: 'clerk-read', effect: 'allow', subject: { role: 'clerk' }, action: 'order.read', resource: 'orders-*' },
				{ id: 'clerk-charge-mfa', effect: 'allow', subject: { role: 'clerk' }, action: 'order.charge', resource: 'orders-*', condition: { mfa: true } },
				{ id: 'admin-override', effect: 'allow', subject: { role: 'admin' }, action: '*', resource: '*' },
				{ id: 'offboarded-deny', effect: 'deny', subject: { flag: 'offboarded' }, action: '*', resource: '*' },
			],
		},
	],
	probes: [
		{ id: 'clerk-read-ok', subject: 'bob', action: 'order.read', resource: 'orders-1041', context: {}, expect: 'allow' },
		{ id: 'clerk-charge-no-mfa', subject: 'bob', action: 'order.charge', resource: 'orders-1041', context: { mfa: false }, expect: 'deny' },
		{ id: 'offboarded-read', subject: 'carol', action: 'order.read', resource: 'orders-1041', expect: 'deny' },
		{ id: 'admin-anything', subject: 'alice', action: 'order.export', resource: 'orders-1041', expect: 'allow' },
	],
}

const authzRequest = (subject, action, resource, context = {}) => ({
	subject,
	action,
	resource,
	context,
})

// --- observability contracts (mirror the unit-test fixture) ------------------

const obsVocabulary = {
	version: 1,
	reviewedOn: '2026-10-01',
	events: [
		{ name: 'order.placed', description: 'An order was accepted and awaits settlement' },
		{ name: 'order.cancelled', description: 'A customer cancelled an open order' },
		{ name: 'payment.settled', description: 'A charge was captured by the payment provider' },
	],
}

const obsLabelSchema = {
	version: 1,
	reviewedOn: '2026-10-01',
	metrics: [
		{ name: 'storefront_requests_total', description: 'Storefront HTTP requests', labels: ['method', 'route', 'status'] },
		{ name: 'payment_settlements_total', description: 'Settlement outcomes', labels: ['result', 'provider'] },
	],
}

const obsBudget = {
	owner: 'Storefront team',
	reviewedOn: '2026-10-01',
	metrics: [
		{
			name: 'storefront_requests_total',
			total: 4000,
			allocations: [
				{ label: 'method', maxValues: 2 },
				{ label: 'route', maxValues: 2 },
				{ label: 'status', maxValues: 100 },
			],
		},
		{
			name: 'payment_settlements_total',
			total: 200,
			allocations: [
				{ label: 'result', maxValues: 2 },
				{ label: 'provider', maxValues: 10 },
			],
		},
	],
}

const obsBudgetWithOrderId = {
	...obsBudget,
	metrics: [
		{
			...obsBudget.metrics[0],
			allocations: [...obsBudget.metrics[0].allocations, { label: 'order_id', maxValues: 50 }],
		},
		obsBudget.metrics[1],
	],
}

const obsLabelSchemaWithOrderId = {
	version: 2,
	reviewedOn: '2026-10-18',
	metrics: [
		{ name: 'storefront_requests_total', description: 'Storefront HTTP requests', labels: ['method', 'route', 'status', 'order_id'] },
		obsLabelSchema.metrics[1],
	],
}

const obsScanCall = (kind, name, labels = []) => ({ file: 'src/storefront.py', line: 6, kind, name, labels })

const obsObservations = [
	{ metric: 'storefront_requests_total', label: 'method', distinct: 2 },
	{ metric: 'storefront_requests_total', label: 'route', distinct: 2 },
	{ metric: 'storefront_requests_total', label: 'status', distinct: 37 },
	{ metric: 'payment_settlements_total', label: 'result', distinct: 2 },
	{ metric: 'payment_settlements_total', label: 'provider', distinct: 3 },
]

const obsBreachObservations = [
	...obsObservations,
	{ metric: 'storefront_requests_total', label: 'order_id', distinct: 1204 },
]

const obsPolicy = await load('obs')

const enclavePolicy = await load('enclave')
const seamPolicy = await load('seam')
const crossPolicy = await load('cross')
const authzPolicy = await load('authz')

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

// --- authz ----------------------------------------------------------------

const decide = (request, policySet) =>
	authzPolicy.evaluate({ request, policySet })[0].result

let d = decide(authzRequest('bob', 'order.read', 'orders-1041'), authzPolicySet)
assert(d.decision === 'allow' && d.rule === 'clerk-read', 'clerk read allowed in wasm')

d = decide(authzRequest('bob', 'order.charge', 'orders-1041', { mfa: false }), authzPolicySet)
assert(
	d.decision === 'deny' && d.rule === 'policy/default-deny',
	'MFA condition not met falls through to default deny in wasm',
)
const mfaStep = d.trace.find((s) => s.rule === 'clerk-charge-mfa')
assert(
	mfaStep && mfaStep.outcome === 'not-matched' && mfaStep.because.includes('context.mfa=true'),
	'the trace names the unmet condition in wasm',
)

const denyBobSet = {
	...authzPolicySet,
	versions: authzPolicySet.versions.map((v) =>
		v.version === 2
			? {
					...v,
					rules: [
						...v.rules,
						{ id: 'bob-frozen', effect: 'deny', subject: { id: 'bob' }, action: '*', resource: '*' },
					],
			  }
			: v,
	),
}
d = decide(authzRequest('bob', 'order.read', 'orders-1041'), denyBobSet)
assert(
	d.decision === 'deny' && d.rule === 'bob-frozen',
	'explicit deny beats a matching allow in wasm',
)

d = decide(authzRequest('ghost', 'order.read', 'orders-1041'), authzPolicySet)
assert(
	d.decision === 'deny' && d.rule === 'policy/default-deny' && d.trace.length > 0,
	'unknown subject fails closed with a trace in wasm',
)

d = decide(authzRequest('bob', 'order.read', 'orders-1041'), { ...authzPolicySet, disabled: true })
assert(
	d.decision === 'deny' && d.rule === 'policy/disabled-fail-closed',
	'disabled policy set fails closed in wasm',
)

// --- obs -------------------------------------------------------------------

const audit = (extra) => obsPolicy.evaluate({
	vocabulary: obsVocabulary,
	labels: obsLabelSchema,
	budget: obsBudget,
	today,
	scan: {
		calls: [
			obsScanCall('event', 'order.placed'),
			obsScanCall('metric', 'storefront_requests_total', ['method', 'route', 'status']),
			obsScanCall('metric', 'payment_settlements_total', ['result', 'provider']),
		],
	},
	observations: obsObservations,
	...extra,
})[0].result

r = audit({})
assert(r.valid === true && r.findings.length === 0 && r.cardinalities.length === 2, 'valid contracts, scan, and export pass the audit in wasm')

r = audit({ scan: { calls: [obsScanCall('event', 'order.refunded')] } })
assert(hasFinding(r, 'lint/event-undeclared'), 'undeclared event name is caught in wasm')

r = audit({ scan: { calls: [obsScanCall('metric', 'storefront_requests_total', ['method', 'route', 'status', 'order_id'])] } })
assert(hasFinding(r, 'lint/label-undeclared'), 'undeclared label on a declared metric is caught in wasm')

r = audit({
	labels: obsLabelSchemaWithOrderId,
	budget: obsBudgetWithOrderId,
	observations: obsBreachObservations,
	budgetFile: 'cardinality-budget.yaml',
})
assert(
	hasFinding(r, 'budget/label-over-allocation') && hasFinding(r, 'budget/metric-total-exceeded') && r.valid === false,
	'budget-breeding label fails the gate in wasm',
)
const overAllocation = r.findings.find((f) => f.rule === 'budget/label-over-allocation')
assert(
	overAllocation.path === '$.budget.metrics[0].allocations[3]' &&
		overAllocation.message.includes('allocates 50 (cardinality-budget.yaml)'),
	'the over-allocation finding cites the exact budget allocation and file',
)
assert(r.cardinalities[0].product === 178192, 'the audit reports the honest product of observed distinct values')

// --- alerts (mirror the unit-test fixture) ---------------------------------

const alertingContract = {
	version: 1,
	reviewedOn: '2026-10-01',
	severityLadder: [
		{ name: 'sev-3', description: "Low-impact degradation on one team's surface", definedOn: '2026-01-15' },
		{ name: 'sev-2', description: 'A customer-visible promise is degraded', definedOn: '2026-01-15' },
		{ name: 'sev-1', description: 'Estate-wide incident; the commander takes the bridge', definedOn: '2026-06-01' },
	],
	runbooks: [
		{ id: 'rb-storefront-5xx', link: 'https://example/runbooks/storefront-5xx.md', escalationClock: 'Acknowledge in 15 minutes; escalate to the storefront on-call lead at 60' },
		{ id: 'rb-payment-provider', link: 'https://example/runbooks/payment-provider.md', escalationClock: 'Acknowledge in 15 minutes; escalate to the payments on-call at 30' },
	],
	alerts: [
		{ id: 'storefront-5xx-rate', owner: 'Storefront team', severity: 'sev-2', runbook: 'rb-storefront-5xx', recordDestination: 'register.yaml' },
		{ id: 'payment-provider-flap', owner: 'Payments team', severity: 'sev-2', runbook: 'rb-payment-provider', recordDestination: 'register.yaml' },
		{ id: 'storefront-latency', owner: 'Storefront team', severity: 'sev-3', runbook: 'rb-storefront-5xx', recordDestination: 'register.yaml' },
	],
}

const incidentRegister = {
	owner: 'Storefront team',
	reviewedOn: '2026-10-19',
	firedAlerts: [
		{ alert: 'storefront-5xx-rate', firedOn: '2026-09-30' },
		{ alert: 'storefront-5xx-rate', firedOn: '2026-10-08' },
		{ alert: 'payment-provider-flap', firedOn: '2026-10-12' },
	],
	incidents: [
		{
			id: 'INC-2026-038',
			detectedOn: '2026-09-30',
			severity: 'sev-1',
			record: 'INC-2026-038 in the incident register',
			alerts: ['storefront-5xx-rate'],
			postmortem: [
				{ id: 'act-038-1', action: 'Remove order_id from the storefront_requests_total labels', closedOn: '2026-10-11', verifiedBy: 'PR #2141 merged; the export shows no order_id label' },
			],
		},
		{ id: 'INC-2026-041', detectedOn: '2026-10-08', severity: 'sev-2', record: 'INC-2026-041 in the incident register', alerts: ['storefront-5xx-rate'], postmortem: [] },
		{ id: 'INC-2026-043', detectedOn: '2026-10-12', severity: 'sev-2', record: 'INC-2026-043 in the incident register', alerts: ['payment-provider-flap'], postmortem: [] },
	],
}

const alertsPolicy = await load('alerts')

const alertsAudit = (alerting, register) =>
	alertsPolicy.evaluate({ alerting, register, today })[0].result

r = alertsAudit(alertingContract, incidentRegister)
assert(
	r.valid === true && r.findings.length === 0 && r.linkages.length === 2,
	'linked alert and register pass the audit in wasm',
)
assert(
	Object.keys(r).sort().join(',') === 'findings,linkages,valid',
	'the audit result shape is exactly {valid, findings, linkages} in wasm',
)

r = alertsAudit(alertingContract, {
	...incidentRegister,
	firedAlerts: [...incidentRegister.firedAlerts, { alert: 'storefront-latency', firedOn: '2026-10-15' }],
})
assert(
	hasFinding(r, 'alerts/no-record-linkage') && r.valid === false,
	'an alert that fired without a record is caught in wasm',
)
const unlinked = r.linkages.find((l) => l.alert === 'storefront-latency')
assert(
	unlinked && unlinked.record === null,
	'the linkage row for the unlinked alert shows NO RECORD (record: null)',
)

r = alertsAudit(alertingContract, {
	...incidentRegister,
	incidents: [
		incidentRegister.incidents[0],
		incidentRegister.incidents[1],
		{ ...incidentRegister.incidents[2], severity: 'sev-0' },
	],
})
assert(hasFinding(r, 'gate/severity-off-ladder'), 'a severity off the ladder is caught in wasm')

r = alertsAudit({
	...alertingContract,
	severityLadder: [
		alertingContract.severityLadder[0],
		alertingContract.severityLadder[1],
		{ ...alertingContract.severityLadder[2], definedOn: today },
	],
}, incidentRegister)
assert(hasFinding(r, 'gate/severity-defined-after-detection'), 'a severity defined after the incident is caught in wasm')

r = alertsAudit(alertingContract, {
	...incidentRegister,
	incidents: [
		incidentRegister.incidents[0],
		{
			...incidentRegister.incidents[1],
			postmortem: [{ id: 'act-041-1', action: 'Gate order_id out of the label schema', closedOn: '2026-10-11' }],
		},
		incidentRegister.incidents[2],
	],
})
assert(hasFinding(r, 'gate/action-unverified'), 'an unverified postmortem action is caught in wasm')

r = alertsAudit({
	...alertingContract,
	runbooks: [{ ...alertingContract.runbooks[0], escalationClock: null }],
}, incidentRegister)
assert(hasFinding(r, 'runbook/escalation-clock-required'), 'a runbook without its escalation clock is caught in wasm')

console.log(process.exitCode ? 'e2e: FAILED' : 'e2e: all assertions passed')

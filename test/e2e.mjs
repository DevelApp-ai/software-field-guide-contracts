// End-to-end smoke test: loads the sixteen policy.wasm builds and evaluates
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
const actionsPolicy = await load('actions')
const erasurePolicy = await load('erasure')
const segmentPolicy = await load('segment')
const ingressPolicy = await load('ingress')
const citizenPolicy = await load('citizen')
const componentPolicy = await load('component')
const matrixPolicy = await load('matrix')
const policyPolicy = await load('policy')
const compliancePolicy = await load('compliance')
const brokerPolicy = await load('broker')

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

// --- actions (mirror the unit-test fixture) ---------------------------------

const actionsRegistry = {
	version: 1,
	reviewedOn: '2026-10-01',
	platformCeilings: { maxTimeoutSeconds: 600, maxMemoryMB: 2048 },
	servers: [
		{ name: 'invoice-service', approved: true },
		{ name: 'courier-api', approved: false },
	],
	actions: [
		{
			id: 'fetch-invoice',
			name: 'Fetch invoice',
			description: 'Retrieve one invoice record from the registered invoice service',
			type: 'ExternalServer',
			parameters: [
				{ name: 'invoiceId', type: 'string', validation: { minLength: 1 } },
			],
			outputs: { invoice: 'object' },
			envelope: { timeoutSeconds: 120, maxMemoryMB: 512, useIsolation: false },
			securityLevel: 'Low',
			confirmation: 'auto-confirm',
			effect: 'read',
			server: { name: 'invoice-service', operation: 'getInvoice', mappings: { invoiceId: 'invoiceId' } },
		},
		{
			id: 'summarize-invoice',
			name: 'Summarize invoice',
			description: 'Produce a plain-language summary of one invoice for the drafting agent',
			type: 'AgenticPrompt',
			parameters: [
				{ name: 'invoiceId', type: 'string', validation: { minLength: 1 } },
			],
			outputs: { summary: 'string' },
			envelope: { timeoutSeconds: 90, maxMemoryMB: 256, useIsolation: false },
			securityLevel: 'Low',
			confirmation: 'auto-confirm',
			effect: 'read',
		},
		{
			id: 'compile-quarterly-report',
			name: 'Compile quarterly report',
			description: 'Run the quarterly reporting script over the ledger in sidecar isolation',
			type: 'PythonScript',
			parameters: [
				{ name: 'quarter', type: 'string', validation: { enumValues: ['Q1', 'Q2', 'Q3', 'Q4'] } },
			],
			outputs: { reportPath: 'string' },
			envelope: { timeoutSeconds: 480, maxMemoryMB: 1024, useIsolation: true },
			securityLevel: 'Standard',
			confirmation: 'auto-confirm',
			effect: 'read',
		},
		{
			id: 'file-draft-chargeback',
			name: 'File draft chargeback',
			description: 'Draft a chargeback case for one disputed invoice and file it for review',
			type: 'CSharpScript',
			parameters: [
				{ name: 'invoiceId', type: 'string', validation: { minLength: 1 } },
				{ name: 'amount', type: 'number', validation: { minimum: 0 } },
			],
			outputs: { caseId: 'string' },
			envelope: { timeoutSeconds: 300, maxMemoryMB: 1024, useIsolation: true },
			securityLevel: 'High',
			confirmation: 'confirm',
			effect: 'write',
		},
		{
			id: 'send-invoice-email',
			name: 'Send invoice email',
			description: 'Send one invoice to one recipient through the registered invoice service',
			type: 'ExternalServer',
			parameters: [
				{ name: 'invoiceId', type: 'string', validation: { minLength: 1 } },
				{ name: 'recipient', type: 'string', validation: { minLength: 1 } },
			],
			outputs: { messageId: 'string' },
			envelope: { timeoutSeconds: 60, maxMemoryMB: 256, useIsolation: false },
			securityLevel: 'Critical',
			confirmation: 'confirm',
			effect: 'write',
			server: { name: 'invoice-service', operation: 'sendInvoiceEmail', mappings: { invoiceId: 'invoiceId', recipient: 'recipient' } },
		},
	],
}

const actionsManifest = {
	owner: 'Billing team',
	reviewedOn: '2026-10-15',
	agents: [
		{
			agent: 'invoice-drafting-agent',
			stage: 'autonomous',
			grants: [
				{ action: 'fetch-invoice', argumentScopes: [{ parameter: 'invoiceId', pattern: 'INV-*' }] },
				{ action: 'summarize-invoice', argumentScopes: [{ parameter: 'invoiceId', pattern: 'INV-*' }] },
			],
		},
		{
			agent: 'chargeback-agent',
			stage: 'propose-only',
			grants: [
				{
					action: 'file-draft-chargeback',
					argumentScopes: [
						{ parameter: 'invoiceId', pattern: 'INV-*' },
						{ parameter: 'amount', pattern: '*' },
					],
				},
			],
		},
		{
			agent: 'archive-reader',
			stage: 'read-only',
			grants: [
				{ action: 'fetch-invoice', argumentScopes: [{ parameter: 'invoiceId', pattern: 'INV-2026-*' }] },
			],
		},
	],
}

const actionsAudit = (extra) => actionsPolicy.evaluate({
	registry: actionsRegistry,
	manifest: actionsManifest,
	today,
	...extra,
})[0].result

r = actionsAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.scoping.length === 3,
	'valid registry and manifest pass the audit in wasm',
)
assert(
	Object.keys(r).sort().join(',') === 'findings,scoping,valid',
	'the audit answers in the stable wasm shape {valid, findings, scoping}',
)
const scoping = Object.fromEntries(r.scoping.map((s) => [s.agent, s]))
assert(
	scoping['invoice-drafting-agent'].stage === 'autonomous' &&
		scoping['invoice-drafting-agent'].actions.join(',') === 'fetch-invoice,summarize-invoice' &&
		scoping['chargeback-agent'].stage === 'propose-only' &&
		scoping['archive-reader'].stage === 'read-only',
	'the scoping reports each agent with its stage and granted actions in wasm',
)

r = actionsAudit({
	registry: {
		...actionsRegistry,
		actions: actionsRegistry.actions.map((a) =>
			a.id === 'fetch-invoice'
				? { ...a, parameters: [{ name: 'invoiceId', type: '', validation: { minLength: 1 } }] }
				: a,
		),
	},
})
assert(hasFinding(r, 'action/parameter-untyped') && r.valid === false, 'untyped parameter is caught in wasm')

r = actionsAudit({
	registry: {
		...actionsRegistry,
		actions: actionsRegistry.actions.map((a) =>
			a.id === 'compile-quarterly-report'
				? { ...a, envelope: { ...a.envelope, timeoutSeconds: 900 } }
				: a,
		),
	},
})
assert(hasFinding(r, 'envelope/exceeds-ceiling') && r.valid === false, 'envelope over the platform ceiling is caught in wasm')

r = actionsAudit({
	registry: {
		...actionsRegistry,
		actions: actionsRegistry.actions.map((a) =>
			a.id === 'send-invoice-email'
				? { ...a, confirmation: 'auto-confirm' }
				: a,
		),
	},
})
assert(hasFinding(r, 'action/confirm-required-at-level') && r.valid === false, 'auto-confirmed Critical action is caught in wasm')

r = actionsAudit({
	manifest: {
		...actionsManifest,
		agents: actionsManifest.agents.map((g) =>
			g.agent === 'chargeback-agent'
				? { ...g, grants: [{ action: 'purge-invoice-archive', argumentScopes: [{ parameter: 'invoiceId', pattern: 'INV-*' }] }] }
				: g,
		),
	},
})
assert(hasFinding(r, 'manifest/action-unknown') && r.valid === false, 'grant for an undeclared action is caught in wasm')

r = actionsAudit({
	manifest: {
		...actionsManifest,
		agents: actionsManifest.agents.map((g) =>
			g.agent === 'archive-reader'
				? { ...g, grants: [...g.grants, { action: 'file-draft-chargeback', argumentScopes: [{ parameter: 'invoiceId', pattern: 'INV-*' }] }] }
				: g,
		),
	},
})
assert(hasFinding(r, 'manifest/stage-contradiction') && r.valid === false, 'read-only agent granted a write is caught in wasm')

// --- erasure (mirror the unit-test fixture) -----------------------------------

const dekRegistry = {
	version: 1,
	reviewedOn: '2026-10-01',
	keys: [
		{ dek: 'tenant-acme-dek-004', tenant: 'tenant-acme', state: 'destroyed', destroyedAt: '2026-10-02', destroyedBy: 'KMS DestroyKey in change CHG-4471; key material unrecoverable, cf. runbook RB-014' },
		{ dek: 'tenant-globex-dek-002', tenant: 'tenant-globex', state: 'destroyed', destroyedAt: '2026-10-06', destroyedBy: 'KMS DestroyKey in change CHG-4488; key material unrecoverable, cf. runbook RB-014' },
		{ dek: 'tenant-initech-dek-001', tenant: 'tenant-initech', state: 'active' },
	],
}

const forgottenCase = {
	owner: 'Platform team',
	reviewedOn: '2026-10-19',
	tenant: 'tenant-acme',
	requestedOn: '2026-10-01',
	requestedBy: 'DSR-2026-041 (tenant offboarding erasure request)',
	status: 'closed',
	stores: [
		{ name: 'postgres-primary', kind: 'primary' },
		{ name: 'postgres-replica-eu', kind: 'replica' },
		{ name: 'corpus-vector-index', kind: 'vector-store' },
		{ name: 'nightly-backups', kind: 'backup', expiresOn: '2026-10-15' },
	],
	sweeps: [
		{ store: 'postgres-primary', sweptOn: '2026-10-02', sweptBy: 'DELETE cascade from the tenant row; 412 rows removed, count verified by the tenant-id scan' },
		{ store: 'postgres-replica-eu', sweptOn: '2026-10-03', sweptBy: 'replica catch-up confirmed; the tenant-id scan returns zero rows on the replica' },
		{ store: 'corpus-vector-index', sweptOn: '2026-10-04', sweptBy: "index rebuild without the tenant's corpus; embedding count verified" },
	],
}

const pendingCase = {
	owner: 'Platform team',
	reviewedOn: '2026-10-19',
	tenant: 'tenant-globex',
	requestedOn: '2026-10-05',
	requestedBy: 'DSR-2026-052 (tenant offboarding erasure request)',
	status: 'open',
	stores: [
		{ name: 'postgres-primary', kind: 'primary' },
		{ name: 'corpus-vector-index', kind: 'vector-store' },
		{ name: 'nightly-backups', kind: 'backup', expiresOn: '2027-01-15' },
	],
	sweeps: [
		{ store: 'postgres-primary', sweptOn: '2026-10-06', sweptBy: 'DELETE cascade from the tenant row; 208 rows removed, count verified by the tenant-id scan' },
		{ store: 'corpus-vector-index', sweptOn: '2026-10-06', sweptBy: "index rebuild without the tenant's corpus; embedding count verified" },
	],
}

const erasureAudit = (extra) => erasurePolicy.evaluate({
	keys: dekRegistry,
	case: forgottenCase,
	today,
	...extra,
})[0].result

r = erasureAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.verdict === 'forgotten' && r.stores.length === 4,
	'destroyed-DEK control passes the audit in wasm',
)
assert(
	Object.keys(r).sort().join(',') === 'findings,stores,valid,verdict',
	'the audit answers in the stable wasm shape {valid, findings, stores, verdict}',
)
const replicaCard = r.stores.find((st) => st.store === 'postgres-replica-eu')
assert(
	replicaCard && replicaCard.verdict === 'swept' && replicaCard.detail === 'swept on 2026-10-03',
	'the store card renders the replica swept on its record day in wasm',
)

r = erasureAudit({ case: pendingCase })
assert(
	r.valid === true && r.verdict === 'pending, honest',
	'the unexpired backup renders pending, honest in wasm',
)
const pendingCard = r.stores.find((st) => st.store === 'nightly-backups')
assert(
	pendingCard && pendingCard.verdict === 'pending' && pendingCard.detail === 'backup window open until 2027-01-15',
	'the pending store row shows the open backup window in wasm',
)

r = erasureAudit({
	case: { ...forgottenCase, sweeps: forgottenCase.sweeps.filter((w) => w.store !== 'postgres-replica-eu') },
})
assert(
	hasFinding(r, 'sweep/store-unswept') && r.valid === false,
	'a replica without its sweep record is caught in wasm',
)
const unswept = r.stores.find((st) => st.store === 'postgres-replica-eu')
assert(unswept && unswept.verdict === 'unswept', 'the unswept store row renders unswept in wasm')

r = erasureAudit({ case: { ...pendingCase, status: 'closed' } })
assert(hasFinding(r, 'case/closed-early') && r.valid === false, 'a case closed on an open backup window is caught in wasm')

r = erasureAudit({ case: { ...forgottenCase, tenant: 'tenant-initech', status: 'open' } })
assert(hasFinding(r, 'keys/dek-not-destroyed') && r.valid === false, 'a live DEK is caught in wasm')


// --- segment (mirror the unit-test fixture) -----------------------------------

const segmentContract = {
	version: 1,
	reviewedOn: '2026-10-01',
	owner: 'Platform team',
	segments: ['web', 'api', 'db', 'worker', 'external'],
	rules: [
		{ id: 'R1', from: 'web', to: 'api', type: 'tcp', port: 443, direction: 'egress', mode: 'enforce' },
		{ id: 'R2', from: 'api', to: 'db', type: 'tcp', port: 5432, direction: 'egress', mode: 'enforce' },
		{ id: 'R3', from: 'worker', to: 'api', type: 'tcp', port: 443, direction: 'egress', mode: 'audit' },
		{
			id: 'R4',
			from: 'external',
			to: 'web',
			type: 'tcp',
			port: 443,
			direction: 'ingress',
			mode: 'enforce',
			exceptions: [{
				reason: "pen-test window — the load generator's traffic is expected until the contract is re-rendered",
				expiresOn: '2026-12-01',
			}],
		},
	],
}

const segmentRenders = {
	version: 1,
	reviewedOn: '2026-10-18',
	fabrics: ['cloud', 'host-firewall'],
	rules: [
		{ fabric: 'cloud', rule: 'R1', direction: 'egress', type: 'tcp', port: 443 },
		{ fabric: 'host-firewall', rule: 'R1', direction: 'egress', type: 'tcp', port: 443 },
		{ fabric: 'cloud', rule: 'R2', direction: 'egress', type: 'tcp', port: 5432 },
		{ fabric: 'host-firewall', rule: 'R2', direction: 'egress', type: 'tcp', port: 5432 },
		{ fabric: 'cloud', rule: 'R3', direction: 'egress', type: 'tcp', port: 443 },
		{ fabric: 'host-firewall', rule: 'R3', direction: 'egress', type: 'tcp', port: 443 },
		{ fabric: 'cloud', rule: 'R4', direction: 'ingress', type: 'tcp', port: 443 },
		{ fabric: 'host-firewall', rule: 'R4', direction: 'ingress', type: 'tcp', port: 443 },
	],
}

const segmentFlows = {
	reviewedOn: '2026-10-16',
	window: { from: '2026-10-01', to: '2026-10-15' },
	flows: [
		{ from: 'web', to: 'api', type: 'tcp', port: 443, count: 812 },
		{ from: 'api', to: 'db', type: 'tcp', port: 5432, count: 147 },
		{ from: 'worker', to: 'api', type: 'tcp', port: 443, count: 14 },
		{ from: 'external', to: 'web', type: 'tcp', port: 443, count: 2105 },
	],
}

const segmentPromotion = {
	pr: 'PR-512',
	rule: 'R3',
	to: 'enforce',
	evidenceFile: 'flows.yaml',
	window: { from: '2026-10-01', to: '2026-10-15' },
}

const segmentAudit = (extra) => segmentPolicy.evaluate({
	contract: segmentContract,
	renders: segmentRenders,
	flows: segmentFlows,
	promotion: segmentPromotion,
	today,
	contractFile: 'segment-contract.yaml',
	rendersFile: 'segment-renders.yaml',
	flowsFile: 'flows.yaml',
	...extra,
})[0].result

r = segmentAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.verdict === 'consistent' && r.rules.length === 4,
	'the segment control passes the audit in wasm and renders consistent',
)
assert(
	Object.keys(r).sort().join(',') === 'findings,rules,valid,verdict',
	'the segment audit answers in the stable wasm shape {valid, findings, rules, verdict}',
)
const r3Card = r.rules.find((c) => c.rule === 'R3')
assert(
	r3Card && r3Card.verdict === 'audit' && /PR-512/.test(r3Card.detail) && /14 matched flows/.test(r3Card.detail),
	'the audit-mode R3 card cites the promotion PR and the matched-flow count in wasm',
)

r = segmentAudit({
	renders: { ...segmentRenders, rules: segmentRenders.rules.filter((row) => !(row.fabric === 'cloud' && row.rule === 'R2')) },
})
assert(
	hasFinding(r, 'render/rule-missing') && r.valid === false,
	'a rule missing from one render is caught in wasm',
)
assert(
	r.findings.some((f) => f.rule === 'render/rule-missing' && /segment-contract\.yaml/.test(f.message) && /segment-renders\.yaml/.test(f.message)),
	'the missing-render finding cites BOTH file names in wasm',
)

r = segmentAudit({
	renders: { ...segmentRenders, rules: [...segmentRenders.rules, { fabric: 'cloud', rule: 'R9', direction: 'egress', type: 'tcp', port: 443 }] },
})
assert(
	hasFinding(r, 'render/rule-unknown') && r.valid === false,
	'a render carrying a rule the contract never had is caught in wasm',
)

r = segmentAudit({
	renders: { ...segmentRenders, rules: segmentRenders.rules.map((row) => row.rule === 'R1' && row.fabric === 'cloud' ? { ...row, direction: 'ingress' } : row) },
})
assert(
	hasFinding(r, 'render/direction-mismatch') && r.valid === false,
	'a direction disagreement inside the modeled subset is caught in wasm',
)

r = segmentAudit({
	promotion: {
		pr: segmentPromotion.pr,
		rule: segmentPromotion.rule,
		to: segmentPromotion.to,
		window: segmentPromotion.window,
	},
})
assert(
	hasFinding(r, 'promotion/no-flow-evidence') && r.valid === false,
	'a promotion without flow evidence fails in wasm',
)

r = segmentAudit({ flows: { ...segmentFlows, flows: segmentFlows.flows.filter((f) => !(f.from === 'api' && f.to === 'db')) } })
assert(
	r.valid === true && r.verdict === 'review' && hasFinding(r, 'flows/dead-rule'),
	'a dead rule flags for review without failing the gate in wasm',
)
const deadCard = r.rules.find((c) => c.rule === 'R2')
assert(deadCard && deadCard.verdict === 'dead', 'the dead R2 card renders dead in wasm')

r = segmentAudit({
	contract: {
		...segmentContract,
		rules: segmentContract.rules.map((rule) => rule.id === 'R4' ? { ...rule, exceptions: [{ reason: rule.exceptions[0].reason, expiresOn: '2026-09-01' }] } : rule),
	},
})
assert(
	hasFinding(r, 'exception/ttl-expired') && r.valid === false && r.verdict === 'inconsistent',
	'a TTL-expired exception makes the composed verdict inconsistent in wasm',
)

// ---- ingress --------------------------------------------------------------
//
// The #82 worked example in wasm: one posture case and its drill record,
// judged by the composed ingress/audit entrypoint — the control renders
// hardened with one card per judged item, and every seeded variant bites
// exactly the way the native demo proves it does.

const ingressCase = {
	version: 1,
	reviewedOn: '2026-10-01',
	owner: 'Platform team',
	zone: 'dev.internal',
	requestPolicy: {
		defaultDeny: true,
		decision: 'deny every request the allowed domains do not admit',
	},
	domains: [
		{ pattern: '*.dev.internal', intent: 'every developer app tenant, inside the platform zone' },
		{ pattern: 'partner.example.com', intent: 'the one external partner host the storefront fronts' },
	],
	certs: [
		{ serves: 'edge.dev.internal', notBefore: '2026-08-01', notAfter: '2027-01-15', rotateByDays: 30 },
		{ serves: 'partner.example.com', notBefore: '2026-07-01', notAfter: '2026-12-15', rotateByDays: 21 },
	],
	slos: [{ name: 'edge availability', target: '99.9% of requests served inside 200ms', pager: 'platform on-call' }],
	routes: [{ class: 'developer-app' }, { class: 'partner-api' }, { class: 'health-check' }],
	loggedRouteClasses: ['developer-app', 'partner-api', 'health-check'],
	killPath: {
		name: 'seal-edge',
		effect: 'the edge denies all ingress and the platform seals inside its zone',
	},
}

const ingressDrill = {
	version: 1,
	reviewedOn: '2026-10-15',
	owner: 'Platform team',
	maxStalenessDays: 180,
	drills: [
		{
			killPath: 'seal-edge',
			drilledOn: '2026-10-10',
			evidence: 'drill log 2026-10-10: seal-edge pulled, all ingress denied for 90 seconds, recovery clean',
		},
	],
}

const ingressAudit = (extra) => ingressPolicy.evaluate({
	case: ingressCase,
	drill: ingressDrill,
	today,
	caseFile: 'ingress-case.yaml',
	drillFile: 'drill.yaml',
	...extra,
})[0].result

r = ingressAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.verdict === 'hardened' && r.cards.length === 10,
	'the ingress control passes the audit in wasm and renders hardened',
)

r = ingressAudit({
	case: { ...ingressCase, domains: [{ pattern: '*.example.com', intent: 'a wildcard the zone cannot hold' }] },
})
assert(
	hasFinding(r, 'domain/too-broad') && r.valid === false && r.verdict === 'exposed',
	'a wildcard beyond the declared zone is caught in wasm',
)

r = ingressAudit({
	case: { ...ingressCase, requestPolicy: { ...ingressCase.requestPolicy, defaultDeny: false } },
})
assert(
	hasFinding(r, 'requestpolicy/default-deny-required') && r.valid === false,
	'an allow list without default-deny is not an allow list in wasm',
)

r = ingressAudit({
	case: {
		...ingressCase,
		certs: ingressCase.certs.map((c) => c.serves === 'edge.dev.internal' ? { ...c, notAfter: '2026-09-30' } : c),
	},
})
assert(
	r.findings.some((f) => f.rule === 'cert/expired' && /edge\.dev\.internal/.test(f.message)) && r.verdict === 'exposed',
	'an expired certificate is an exposure in wasm, naming the host it served',
)

r = ingressAudit({
	case: {
		...ingressCase,
		certs: ingressCase.certs.map((c) => c.serves === 'edge.dev.internal' ? { ...c, notAfter: '2026-11-10' } : c),
	},
})
assert(
	hasFinding(r, 'cert/near-expiry') && r.valid === true && r.verdict === 'review',
	'a certificate inside its rotation window flags for review in wasm, not failure',
)

r = ingressAudit({
	case: { ...ingressCase, slos: [{ name: 'edge availability', target: '99.9% of requests served inside 200ms' }] },
})
assert(
	hasFinding(r, 'slo/pager-required') && r.valid === false,
	'an SLO without its pager is a promise nobody keeps in wasm',
)

r = ingressAudit({
	case: { ...ingressCase, loggedRouteClasses: ['developer-app', 'health-check'] },
})
assert(
	r.findings.some((f) => f.rule === 'audit/class-unlogged' && /partner-api/.test(f.message)) && r.valid === false,
	'a declared route class the audit never logs is caught in wasm, naming the class',
)

r = ingressAudit({ drill: { ...ingressDrill, drills: [] } })
assert(
	hasFinding(r, 'killpath/never-rehearsed') && r.valid === false && r.verdict === 'exposed',
	'a kill path declared but never rehearsed fails the gate in wasm',
)

r = ingressAudit({
	drill: {
		...ingressDrill,
		drills: [{ killPath: 'seal-edge', drilledOn: '2026-02-10', evidence: 'drill log 2026-02-10' }],
	},
})
assert(
	hasFinding(r, 'killpath/stale-rehearsal') && r.valid === true && r.verdict === 'review',
	'a rehearsal grown stale flags for review in wasm, not failure',
)

r = ingressAudit({
	drill: {
		...ingressDrill,
		drills: [{ killPath: 'seal-edge', drilledOn: '2026-12-01', evidence: 'drill log 2026-12-01' }],
	},
})
assert(
	hasFinding(r, 'drill/future-dated') && hasFinding(r, 'killpath/never-rehearsed'),
	'a future-dated drill never counts as the rehearsal the kill path needs in wasm',
)

r = ingressAudit({
	drill: {
		...ingressDrill,
		drills: [
			...ingressDrill.drills,
			{ killPath: 'seal-the-vault', drilledOn: '2026-10-12', evidence: 'drill log 2026-10-12' },
		],
	},
})
assert(
	r.findings.some((f) => f.rule === 'drill/killpath-unknown' && /ingress-case\.yaml/.test(f.message) && /drill\.yaml/.test(f.message)),
	'a rehearsal for a kill path the case never declared is caught in wasm, citing both files',
)

// --- citizen --------------------------------------------------------------
//
// Judged by the composed citizen/audit entrypoint — the control
// renders aligned with one card per judged item, every seeded drift
// is advised (an advisor, not a blocker: the gate stays green with
// the advice on the record), and a manifest the advisor cannot read
// fails honestly.

const citizenManifest = {
	version: 1,
	reviewedOn: '2026-10-01',
	owner: 'Storefront team',
	app: 'expense-approver',
	components: [
		{ name: 'claim-form', behavior: 'submits an expense claim' },
		{ name: 'claim-rules', behavior: 'approves a claim inside its policy' },
	],
	dataBindings: [
		{ name: 'claims-store', mode: 'read', via: 'platform-data-api' },
		{ name: 'audit-log', mode: 'write', via: 'platform-data-api' },
	],
	actions: ['expense.submit', 'expense.approve'],
	guardrails: [
		{ name: 'data-guardrail', version: 3 },
		{ name: 'action-guardrail', version: 2 },
	],
}

const citizenSpec = {
	version: 1,
	reviewedOn: '2026-10-01',
	owner: 'Storefront team',
	actions: ['expense.submit', 'expense.approve'],
	coverage: ['submits an expense claim', 'approves a claim inside its policy'],
}

const citizenRegistry = {
	version: 1,
	reviewedOn: '2026-10-15',
	owner: 'Platform team',
	dataRails: ['platform-data-api'],
	platformFloor: [
		{ name: 'data-guardrail', floor: 3 },
		{ name: 'action-guardrail', floor: 2 },
	],
}

const citizenAudit = (extra) => citizenPolicy.evaluate({
	manifest: citizenManifest,
	spec: citizenSpec,
	registry: citizenRegistry,
	today,
	manifestFile: 'manifest.yaml',
	specFile: 'spec.yaml',
	registryFile: 'guardrails.yaml',
	...extra,
})[0].result

r = citizenAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.verdict === 'aligned' && r.cards.length === 8,
	'the citizen control passes the audit in wasm and renders aligned',
)

r = citizenAudit({
	manifest: {
		...citizenManifest,
		dataBindings: citizenManifest.dataBindings.map((b) => b.name === 'audit-log' ? { ...b, via: 'raw-sql' } : b),
	},
})
assert(
	hasFinding(r, 'binding/escape-hatch') && r.valid === true && r.verdict === 'advises changes',
	'an escape hatch is advised in wasm and the gate stays green',
)
assert(
	r.findings.some((f) => f.rule === 'binding/escape-hatch' && /manifest\.yaml/.test(f.message) && /guardrails\.yaml/.test(f.message)),
	'the escape-hatch advice cites both files in wasm',
)
assert(
	r.cards.some((c) => c.area === 'data bindings' && c.verdict === 'advises'),
	'the binding card renders advises in wasm',
)

r = citizenAudit({
	manifest: { ...citizenManifest, actions: [...citizenManifest.actions, 'expense.purge'] },
})
assert(
	hasFinding(r, 'action/outside-rails') && r.valid === true && r.verdict === 'advises changes',
	'an action outside the rails the spec granted is advised in wasm, never blocked',
)

r = citizenAudit({
	manifest: {
		...citizenManifest,
		components: citizenManifest.components.map((c) => c.name === 'claim-rules' ? { ...c, behavior: 'deletes old claims' } : c),
	},
})
assert(
	hasFinding(r, 'behavior/uncovered-by-spec') && r.valid === true && r.verdict === 'advises changes',
	'a behavior without spec coverage is advised in wasm',
)

r = citizenAudit({
	manifest: {
		...citizenManifest,
		guardrails: citizenManifest.guardrails.map((g) => g.name === 'data-guardrail' ? { ...g, version: 2 } : g),
	},
})
assert(
	hasFinding(r, 'guardrail/below-floor') && r.valid === true && r.verdict === 'advises changes',
	'a guardrail below the platform floor is advised in wasm',
)

r = citizenAudit({
	manifest: {
		...citizenManifest,
		guardrails: [...citizenManifest.guardrails, { name: 'review-guardrail', version: 1 }],
	},
})
assert(
	hasFinding(r, 'guardrail/unknown') && r.valid === true && r.verdict === 'advises changes',
	'a guardrail the registry never heard of is advised in wasm',
)

r = citizenAudit({ manifest: { ...citizenManifest, version: null } })
assert(
	hasFinding(r, 'manifest/version-required') && r.valid === false && r.verdict === 'unreadable',
	'a manifest the advisor cannot read fails honestly in wasm',
)

// --- component ------------------------------------------------------------
//
// Judged by the composed component/audit entrypoint — the control
// renders consistent with one card per judged item, and every seeded
// drift is refused (a conformance gate, not an advisor: the package
// does not ship until the drift is fixed).

const componentPackage = {
	component: 'payments-checkout',
	version: '1.4.0',
	hierarchy: 'customer',
	reviewedOn: '2026-10-01',
	owner: 'Payments team',
	artifactDigest: '5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c',
	signature: {
		keyId: 'key-2026-q4',
		signedDigest: '5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c',
	},
	attestation: {
		statement: 'the checkout artifact was built by the release pipeline',
		by: 'release pipeline',
	},
	provenance: {
		source: 'payments/checkout.git',
		commit: '9f31c0e',
	},
	dependencies: [
		{ package: 'platform-baseline', digest: 'd6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44' },
	],
}

const componentRegistry = {
	version: 1,
	reviewedOn: '2026-10-15',
	owner: 'Platform team',
	packages: [
		{ component: 'payments-checkout', version: '1.4.0', hierarchy: 'customer', digest: '5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c' },
		{ component: 'platform-baseline', version: '2.1.0', hierarchy: 'general', digest: 'd6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44' },
		{ component: 'storefront-theme', version: '0.3.0', hierarchy: 'project', digest: '6053401fe5190a3153158f3173dd0f0212e3d0270be5ff30289a76495988e875' },
	],
}

const componentAudit = (extra) => componentPolicy.evaluate({
	package: componentPackage,
	registry: componentRegistry,
	today,
	packageFile: 'package.yaml',
	registryFile: 'registry.yaml',
	...extra,
})[0].result

r = componentAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.verdict === 'consistent' && r.cards.length === 2,
	'the component control passes the audit in wasm and renders consistent',
)

r = componentAudit({ package: { ...componentPackage, version: '1.5.0' } })
assert(
	hasFinding(r, 'gate/package-unregistered') && r.valid === false && r.verdict === 'drifts',
	'an unregistered package is refused in wasm',
)
assert(
	r.findings.some((f) => f.rule === 'gate/package-unregistered' && /package\.yaml/.test(f.message) && /registry\.yaml/.test(f.message)),
	'the unregistered-package finding cites both files in wasm',
)

r = componentAudit({
	package: {
		...componentPackage,
		artifactDigest: '4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80',
		signature: { keyId: 'key-2026-q4', signedDigest: '4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80' },
	},
})
assert(
	hasFinding(r, 'gate/package-digest-drift') && r.valid === false && r.verdict === 'drifts',
	'an artifact drifted from its registration is refused in wasm',
)

r = componentAudit({
	package: {
		...componentPackage,
		dependencies: [{ package: 'platform-baseline', digest: 'aaf1965eeee9f4c7eaf29bbb5b32eb477629a35c41d21dd75037af59b0ee8e1c' }],
	},
})
assert(
	hasFinding(r, 'gate/dependency-digest-mismatch') && r.valid === false && r.verdict === 'drifts',
	'a stale pin is refused in wasm',
)
assert(
	r.cards.some((c) => c.area === 'dependencies' && c.verdict === 'drifts'),
	'the dependency card renders drifts in wasm',
)

r = componentAudit({
	package: {
		...componentPackage,
		dependencies: [{ package: 'storefront-theme', digest: '6053401fe5190a3153158f3173dd0f0212e3d0270be5ff30289a76495988e875' }],
	},
})
assert(
	hasFinding(r, 'gate/dependency-hierarchy-violation') && r.valid === false && r.verdict === 'drifts',
	'a customer-tier package depending downward is refused in wasm',
)

r = componentAudit({ package: { ...componentPackage, signature: { keyId: 'key-2026-q4', signedDigest: '4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80' } } })
assert(
	hasFinding(r, 'signature/digest-mismatch') && r.valid === false && r.verdict === 'unreadable',
	'an internally inconsistent signature fails honestly in wasm',
)

r = componentAudit({ package: { ...componentPackage, version: null } })
assert(
	hasFinding(r, 'package/version-required') && r.valid === false && r.verdict === 'unreadable',
	'a package the gate cannot read fails honestly in wasm',
)

// --- matrix ----------------------------------------------------------------
//
// Judged by the composed matrix/audit entrypoint — the control
// renders consistent with one card per declared fabric, and every
// seeded drift is refused (a conformance gate, not an advisor: the
// renders are not believed until every fabric agrees).

const matrixPackage = {
	...componentPackage,
	policyBindings: [
		{ policy: 'pci-scan', path: '/policies/pci-scan.rego' },
		{ policy: 'tier-egress', path: '/policies/tier-egress.rego' },
	],
}

const matrixRenders = {
	version: 1,
	reviewedOn: '2026-10-18',
	owner: 'Platform team',
	component: 'payments-checkout',
	fabrics: ['azure-west-europe', 'aws-eu-central', 'onprem-vsphere'],
	renders: [
		{
			fabric: 'azure-west-europe',
			version: '1.4.0',
			digest: '5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c',
			bindings: [
				{ policy: 'pci-scan', path: '/policies/pci-scan.rego' },
				{ policy: 'tier-egress', path: '/policies/tier-egress.rego' },
			],
		},
		{
			fabric: 'aws-eu-central',
			version: '1.4.0',
			digest: '5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c',
			bindings: [
				{ policy: 'pci-scan', path: '/policies/pci-scan.rego' },
				{ policy: 'tier-egress', path: '/policies/tier-egress.rego' },
			],
		},
		{
			fabric: 'onprem-vsphere',
			version: '1.4.0',
			digest: '5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c',
			bindings: [
				{ policy: 'pci-scan', path: '/policies/pci-scan.rego' },
				{ policy: 'tier-egress', path: '/policies/tier-egress.rego' },
			],
		},
	],
}

const matrixAudit = (extra) => matrixPolicy.evaluate({
	package: matrixPackage,
	matrix: matrixRenders,
	today,
	packageFile: 'package.yaml',
	matrixFile: 'matrix.yaml',
	...extra,
})[0].result

r = matrixAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.verdict === 'consistent' && r.fabrics.length === 3,
	'the matrix control passes the audit in wasm and renders consistent',
)

r = matrixAudit({ matrix: { ...matrixRenders, renders: matrixRenders.renders.map((x) => x.fabric === 'aws-eu-central' ? { ...x, version: '1.3.0' } : x) } })
assert(
	hasFinding(r, 'gate/render-version-skew') && r.valid === false && r.verdict === 'drifts',
	'a fabric on another release is refused in wasm',
)

r = matrixAudit({ matrix: { ...matrixRenders, renders: matrixRenders.renders.map((x) => x.fabric === 'onprem-vsphere' ? { ...x, digest: '4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80' } : x) } })
assert(
	hasFinding(r, 'gate/render-digest-drift') && r.valid === false && r.verdict === 'drifts',
	'a re-render that swapped the artifact is refused in wasm',
)

r = matrixAudit({ matrix: { ...matrixRenders, renders: matrixRenders.renders.map((x) => x.fabric === 'aws-eu-central' ? { ...x, bindings: x.bindings.filter((b) => b.policy !== 'tier-egress') } : x) } })
assert(
	hasFinding(r, 'gate/binding-missing') && r.valid === false && r.verdict === 'drifts',
	'a declared binding a fabric never ran is refused in wasm',
)
assert(
	r.fabrics.some((c) => c.fabric === 'aws-eu-central' && c.verdict === 'drifts'),
	'the fabric card renders drifts in wasm',
)

r = matrixAudit({ matrix: { ...matrixRenders, renders: matrixRenders.renders.map((x) => x.fabric === 'onprem-vsphere' ? { ...x, bindings: [...x.bindings, { policy: 'shadow-scan', path: '/policies/shadow-scan.rego' }] } : x) } })
assert(
	hasFinding(r, 'gate/binding-undeclared') && r.valid === false && r.verdict === 'drifts',
	'a binding in force the package never declared is refused in wasm',
)

r = matrixAudit({ matrix: { ...matrixRenders, renders: matrixRenders.renders.filter((x) => x.fabric !== 'onprem-vsphere') } })
assert(
	hasFinding(r, 'gate/fabric-unrendered') && r.valid === false && r.verdict === 'drifts',
	'a fabric with no render at all is refused in wasm',
)

r = matrixAudit({ matrix: { ...matrixRenders, component: 'storefront-theme' } })
assert(
	hasFinding(r, 'gate/component-mismatch') && r.valid === false && r.verdict === 'drifts',
	'a matrix for another component is refused in wasm',
)

r = matrixAudit({ matrix: { ...matrixRenders, reviewedOn: '2024-10-01' } })
assert(
	hasFinding(r, 'matrix/reviewed-stale') && r.valid === false && r.verdict === 'unreadable',
	'a matrix nobody re-reads fails honestly in wasm',
)

// --- policy ----------------------------------------------------------------
//
// Judged by the composed policy/audit entrypoint — the control
// renders consistent with one card per bound policy, and every
// seeded drift is refused (a conformance gate, not an advisor: the
// same catalog backs many packages, and no row is a drift by
// inventory).

const policyCatalog = {
	version: 1,
	reviewedOn: '2026-10-18',
	owner: 'Platform team',
	policies: [
		{
			policy: 'pci-scan',
			version: '3.2.0',
			digest: 'b09dcc492429e5e410c918a3d27911639f00759d86cd5d87612a23e15e11c324',
			signature: { keyId: 'key-2026-q4', signedDigest: 'b09dcc492429e5e410c918a3d27911639f00759d86cd5d87612a23e15e11c324' },
			posture: 'enforce',
			path: '/policies/pci-scan.rego',
		},
		{
			policy: 'tier-egress',
			version: '1.1.0',
			digest: '54e34a23f2c451616380d3c5432537f6e7d3df96a88e3361cc2b9674f5c289fc',
			signature: { keyId: 'key-2026-q4', signedDigest: '54e34a23f2c451616380d3c5432537f6e7d3df96a88e3361cc2b9674f5c289fc' },
			posture: 'enforce',
			path: '/policies/tier-egress.rego',
		},
		{
			policy: 'allowed-regions',
			version: '1.0.3',
			digest: 'd52c2699e01724cc10fa923fc03b0880698070aa87db78bcb7c77100fe306480',
			signature: { keyId: 'key-2026-q4', signedDigest: 'd52c2699e01724cc10fa923fc03b0880698070aa87db78bcb7c77100fe306480' },
			posture: 'audit',
			path: '/policies/allowed-regions.rego',
		},
	],
}

const policyPackage = {
	...componentPackage,
	policyBindings: [
		{ policy: 'pci-scan', path: '/policies/pci-scan.rego' },
		{ policy: 'tier-egress', path: '/policies/tier-egress.rego' },
	],
}

const policyAudit = (extra) => policyPolicy.evaluate({
	catalog: policyCatalog,
	package: policyPackage,
	today,
	catalogFile: 'catalog.yaml',
	packageFile: 'package.yaml',
	...extra,
})[0].result

r = policyAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.verdict === 'consistent' && r.policies.length === 2,
	'the policy control passes the audit in wasm and renders consistent',
)

r = policyAudit({ catalog: { ...policyCatalog, policies: policyCatalog.policies.filter((x) => x.policy !== 'tier-egress') } })
assert(
	hasFinding(r, 'gate/policy-unresolved') && r.valid === false && r.verdict === 'drifts',
	'a binding to a policy the catalog never declared is refused in wasm',
)
assert(
	r.policies.some((c) => c.policy === 'tier-egress' && c.verdict === 'drifts'),
	'the unresolved-binding card renders drifts in wasm',
)

r = policyAudit({ package: { ...policyPackage, policyBindings: [{ policy: 'pci-scan', path: '/policies/pci-scan.rego' }, { policy: 'tier-egress', path: '/policies/tier-egress-v2.rego' }] } })
assert(
	hasFinding(r, 'gate/binding-path-drift') && r.valid === false && r.verdict === 'drifts',
	'a binding rendered at a path the catalog never named is refused in wasm',
)

r = policyAudit({ catalog: { ...policyCatalog, policies: policyCatalog.policies.map((x) => x.policy === 'pci-scan' ? { ...x, path: '/policies/pci-*.rego' } : x) } })
assert(
	hasFinding(r, 'policy/path-glob') && r.valid === false && r.verdict === 'unreadable',
	'a glob-shaped catalog path fails honestly in wasm',
)

r = policyAudit({ catalog: { ...policyCatalog, policies: policyCatalog.policies.map((x) => x.policy === 'pci-scan' ? { ...x, signature: undefined } : x) } })
assert(
	hasFinding(r, 'policy/signature-required') && r.valid === false && r.verdict === 'unreadable',
	'an unsigned policy component fails honestly in wasm',
)

r = policyAudit({ package: { ...policyPackage, policyBindings: [{ policy: 'pci-scan', path: '/policies/pci-*.rego' }, { policy: 'tier-egress', path: '/policies/tier-egress.rego' }] } })
assert(
	hasFinding(r, 'package/binding-path-glob') && r.valid === false && r.verdict === 'unreadable',
	'a glob-shaped package binding fails honestly in wasm',
)

// --- compliance -----------------------------------------------------------

const complianceControls = {
	version: 1,
	reviewedOn: '2026-10-18',
	owner: 'Platform team',
	evidenceSources: [
		{ id: 'edge-firewall-review', kind: 'review record', status: 'live' },
		{ id: 'encryption-config-scan', kind: 'scanner output', status: 'live' },
		{ id: 'edge-access-logs', kind: 'log store', status: 'live' },
		{ id: 'erasure-case-registry', kind: 'case registry', status: 'live' },
	],
	controls: [
		{
			id: 'CTRL-01',
			title: 'Edge firewall rule set reviewed and re-approved quarterly',
			owner: 'Platform team',
			requirements: ['PCI-DSS-2.2.7'],
			evidenceSource: 'edge-firewall-review',
			reviewedOn: '2026-09-15',
			intervalDays: 180,
		},
		{
			id: 'CTRL-02',
			title: 'Data-at-rest encryption verified by the nightly config scan',
			owner: 'Storefront team',
			requirements: ['PCI-DSS-3.4.1'],
			evidenceSource: 'encryption-config-scan',
			reviewedOn: '2026-10-10',
			intervalDays: 90,
		},
		{
			id: 'CTRL-03',
			title: 'Edge access restricted to authenticated identities',
			owner: 'Platform team',
			requirements: ['SOC2-CC6.1'],
			evidenceSource: 'edge-access-logs',
			reviewedOn: '2026-10-05',
			intervalDays: 90,
		},
		{
			id: 'CTRL-04',
			title: 'Erasure cases closed inside the thirty-day window',
			owner: 'Platform team',
			requirements: ['GDPR-ART-17'],
			evidenceSource: 'erasure-case-registry',
			reviewedOn: '2026-07-01',
			intervalDays: 180,
		},
	],
}

const complianceRequirements = {
	version: 1,
	reviewedOn: '2026-10-01',
	owner: 'Compliance team',
	requirements: [
		{ id: 'PCI-DSS-2.2.7', title: 'Firewall and router rule sets are reviewed and re-approved at least every six months', source: 'PCI DSS v4.0' },
		{ id: 'PCI-DSS-3.4.1', title: 'Cardholder data is rendered unreadable wherever it is stored', source: 'PCI DSS v4.0' },
		{ id: 'SOC2-CC6.1', title: 'Logical access to infrastructure is restricted to authorized users', source: 'SOC 2 Type II, CC6.1' },
		{ id: 'GDPR-ART-17', title: 'Personal data is erased within thirty days of a verified erasure request', source: 'GDPR art. 17' },
	],
}

const complianceAudit = (extra) => compliancePolicy.evaluate({
	controls: complianceControls,
	requirements: complianceRequirements,
	today,
	controlsFile: 'controls.yaml',
	requirementsFile: 'requirements.yaml',
	...extra,
})[0].result

r = complianceAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.verdict === 'consistent' && r.requirements.length === 4,
	'the compliance control pair passes the audit in wasm and renders consistent',
)

r = complianceAudit({ requirements: { ...complianceRequirements, requirements: [...complianceRequirements.requirements, { id: 'ISO-27001-A.5.1', title: 'Access rights are subject to an access control policy', source: 'ISO/IEC 27001 A.5.1' }] } })
assert(
	hasFinding(r, 'gate/requirement-unmapped') && r.valid === false && r.verdict === 'drifts',
	'a requirement nobody controls is refused in wasm',
)

r = complianceAudit({ controls: { ...complianceControls, evidenceSources: complianceControls.evidenceSources.map((s) => s.id === 'encryption-config-scan' ? { ...s, status: 'retired' } : s) } })
assert(
	hasFinding(r, 'gate/evidence-dead') && r.valid === false && r.verdict === 'drifts',
	'a control citing retired evidence is refused in wasm',
)

r = complianceAudit({ controls: { ...complianceControls, controls: complianceControls.controls.map((c) => c.id === 'CTRL-04' ? { ...c, reviewedOn: '2026-08-15', intervalDays: 30 } : c) } })
assert(
	hasFinding(r, 'gate/review-expired') && r.valid === false && r.verdict === 'drifts',
	'a control whose review clock lapsed is refused in wasm',
)

r = complianceAudit({ controls: { ...complianceControls, controls: complianceControls.controls.map((c) => c.id === 'CTRL-02' ? { ...c, requirements: ['ISO-27001-A.5.1'] } : c) } })
assert(
	hasFinding(r, 'gate/requirement-unknown') && r.valid === false && r.verdict === 'drifts',
	'a control mapping onto a requirement nobody wrote is refused in wasm',
)

r = complianceAudit({ controls: { ...complianceControls, controls: complianceControls.controls.map((c) => c.id === 'CTRL-02' ? { ...c, evidenceSource: undefined } : c) } })
assert(
	hasFinding(r, 'control/evidence-required') && r.valid === false && r.verdict === 'unreadable',
	'a control without evidence fails honestly in wasm',
)

r = complianceAudit({ controls: { ...complianceControls, reviewedOn: '2025-09-15' } })
assert(
	hasFinding(r, 'controls/reviewed-stale') && r.valid === false && r.verdict === 'unreadable',
	'a controls manifest nobody re-reads fails honestly in wasm',
)


// --- broker ----------------------------------------------------------------
//
// Judged by the composed broker/audit entrypoint — the control
// grants pass with one card per issued grant, and every seeded
// scope failure is refused (a conformance gate, not an advisor:
// the grants are not believed until the manifest vouches for every
// one at exactly its pinned digest, for a declared principal, with
// an exact action set and the clock still on it).

const brokerGrants = {
	version: 1,
	reviewedOn: '2026-10-18',
	owner: 'Platform team',
	principals: ['storefront-build', 'payments-build'],
	grants: [
		{
			principal: 'storefront-build',
			component: 'payments-checkout',
			digest: '5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c',
			actions: ['pull'],
			expires: '2026-12-31',
		},
		{
			principal: 'payments-build',
			component: 'platform-baseline',
			digest: 'd6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44',
			actions: ['pull', 'attest'],
			expires: '2027-01-31',
		},
	],
}

const brokerAudit = (extra) => brokerPolicy.evaluate({
	broker: brokerGrants,
	package: componentPackage,
	today,
	brokerFile: 'grants.yaml',
	packageFile: 'package.yaml',
	...extra,
})[0].result

r = brokerAudit({})
assert(
	r.valid === true && r.findings.length === 0 && r.verdict === 'consistent' && r.grants.length === 2,
	'the broker control passes the audit in wasm with one card per issued grant',
)

r = brokerAudit({ broker: { ...brokerGrants, grants: brokerGrants.grants.map((g) => g.principal === 'storefront-build' ? { ...g, component: 'storefront-theme' } : g) } })
assert(
	hasFinding(r, 'gate/component-unresolved') && r.valid === false && r.verdict === 'drifts',
	'a grant for a component the manifest never named is refused in wasm',
)
assert(
	r.grants.some((c) => c.principal === 'storefront-build' && c.verdict === 'drifts'),
	'the unresolved grant card renders drifts in wasm',
)

r = brokerAudit({ broker: { ...brokerGrants, grants: brokerGrants.grants.map((g) => g.principal === 'storefront-build' ? { ...g, digest: 'a75f47bd3c7d7f1bcaf4a76a163ed589b5f26708b44996a37ee7f789e9c31c15' } : g) } })
assert(
	hasFinding(r, 'gate/digest-drift') && r.valid === false && r.verdict === 'drifts',
	'a grant pinned at a digest the package never published is refused in wasm',
)

r = brokerAudit({ broker: { ...brokerGrants, grants: brokerGrants.grants.map((g) => g.principal === 'storefront-build' ? { ...g, actions: ['*'] } : g) } })
assert(
	hasFinding(r, 'grant/action-wildcard') && r.valid === false && r.verdict === 'unreadable',
	'a wildcard grant is refused in wasm',
)
assert(
	r.grants.some((c) => c.principal === 'storefront-build' && c.verdict === 'drifts'),
	'the wildcard grant card renders drifts in wasm',
)

r = brokerAudit({ broker: { ...brokerGrants, grants: brokerGrants.grants.map((g) => g.principal === 'storefront-build' ? { ...g, actions: ['pull*'] } : g) } })
assert(
	hasFinding(r, 'grant/action-glob') && r.valid === false && r.verdict === 'unreadable',
	'a metacharacter action is refused in wasm',
)

r = brokerAudit({ broker: { ...brokerGrants, grants: brokerGrants.grants.map((g) => g.principal === 'storefront-build' ? { ...g, expires: '2026-10-01' } : g) } })
assert(
	hasFinding(r, 'grant/expires-in-past') && r.valid === false && r.verdict === 'unreadable',
	'an expired grant still on the books is refused in wasm',
)
assert(
	r.grants.some((c) => c.principal === 'storefront-build' && c.verdict === 'drifts')
		&& r.grants.some((c) => c.principal === 'payments-build' && c.verdict === 'consistent'),
	'the expired grant card renders drifts, the live card stays consistent, in wasm',
)

r = brokerAudit({ broker: { ...brokerGrants, grants: brokerGrants.grants.map((g) => g.principal === 'storefront-build' ? { ...g, principal: 'quarantine-scanner' } : g) } })
assert(
	hasFinding(r, 'grant/principal-undeclared') && r.valid === false && r.verdict === 'unreadable',
	'an identity the broker never declared is refused in wasm',
)
console.log(process.exitCode ? 'e2e: FAILED' : 'e2e: all assertions passed')

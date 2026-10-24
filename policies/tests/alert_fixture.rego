# Shared fixture for the alerts tests: one small, valid alerting contract
# and incident register in the storefront flavor of the book's examples —
# a three-rung severity ladder with dated rungs, two runbooks with
# escalation clocks, three alert rules with owners and record
# destinations, and a register with two linked incidents.
#
# The ladder dates, detection dates, and review dates are chosen
# relative to the CI anchor date 2026-10-20.
package alerts.fixture

import rego.v1

today := "2026-10-20"

contract := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"severityLadder": [
		{"name": "sev-3", "description": "Low-impact degradation on one team's surface", "definedOn": "2026-01-15"},
		{"name": "sev-2", "description": "A customer-visible promise is degraded", "definedOn": "2026-01-15"},
		{"name": "sev-1", "description": "Estate-wide incident; the commander takes the bridge", "definedOn": "2026-06-01"},
	],
	"runbooks": [
		{
			"id": "rb-storefront-5xx",
			"link": "https://example/runbooks/storefront-5xx.md",
			"escalationClock": "Acknowledge in 15 minutes; escalate to the storefront on-call lead at 60",
		},
		{
			"id": "rb-payment-provider",
			"link": "https://example/runbooks/payment-provider.md",
			"escalationClock": "Acknowledge in 15 minutes; escalate to the payments on-call at 30",
		},
	],
	"alerts": [
		{
			"id": "storefront-5xx-rate",
			"owner": "Storefront team",
			"severity": "sev-2",
			"runbook": "rb-storefront-5xx",
			"recordDestination": "register.yaml",
		},
		{
			"id": "payment-provider-flap",
			"owner": "Payments team",
			"severity": "sev-2",
			"runbook": "rb-payment-provider",
			"recordDestination": "register.yaml",
		},
		{
			"id": "storefront-latency",
			"owner": "Storefront team",
			"severity": "sev-3",
			"runbook": "rb-storefront-5xx",
			"recordDestination": "register.yaml",
		},
	],
}

register := {
	"owner": "Storefront team",
	"reviewedOn": "2026-10-19",
	"firedAlerts": [
		{"alert": "storefront-5xx-rate", "firedOn": "2026-09-30"},
		{"alert": "storefront-5xx-rate", "firedOn": "2026-10-08"},
		{"alert": "payment-provider-flap", "firedOn": "2026-10-12"},
	],
	"incidents": [
		{
			"id": "INC-2026-038",
			"detectedOn": "2026-09-30",
			"severity": "sev-1",
			"record": "INC-2026-038 in the incident register",
			"alerts": ["storefront-5xx-rate"],
			"postmortem": [
				{
					"id": "act-038-1",
					"action": "Remove order_id from the storefront_requests_total labels",
					"closedOn": "2026-10-11",
					"verifiedBy": "PR #2141 merged; the export shows no order_id label",
				},
			],
		},
		{
			"id": "INC-2026-041",
			"detectedOn": "2026-10-08",
			"severity": "sev-2",
			"record": "INC-2026-041 in the incident register",
			"alerts": ["storefront-5xx-rate"],
			"postmortem": [],
		},
		{
			"id": "INC-2026-043",
			"detectedOn": "2026-10-12",
			"severity": "sev-2",
			"record": "INC-2026-043 in the incident register",
			"alerts": ["payment-provider-flap"],
			"postmortem": [],
		},
	],
}

validate_input(alerting) := {
	"alerting": alerting,
	"today": today,
}

gate_input(alerting, reg) := {
	"alerting": alerting,
	"register": reg,
	"today": today,
}

# The contract with one rung's definedOn moved past a given date.
with_rung_defined_on(contract, name, date) := object.union(contract, {
	"severityLadder": [object.union(r, rung_override(r, name, date)) |
		some r in contract.severityLadder
	],
})

rung_override(r, name, date) := {"definedOn": date} if object.get(r, "name", null) == name

rung_override(r, name, date) := {} if object.get(r, "name", null) != name

# The register with one incident's severity changed.
with_incident_severity(reg, id, severity) := object.union(reg, {
	"incidents": [object.union(i, incident_override(i, id, severity)) |
		some i in reg.incidents
	],
})

incident_override(i, id, severity) := {"severity": severity} if object.get(i, "id", null) == id

incident_override(i, id, severity) := {} if object.get(i, "id", null) != id

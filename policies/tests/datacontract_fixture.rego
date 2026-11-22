# Shared fixture for the data contract tests: one small, valid
# data contract estate after the enforceable-data-contracts
# chapter's worked example — the payments team's settlement dataset,
# bound to its schema, promised fresh within 24 hours, held to its
# quality thresholds, owned, named to its consumers, enforced by
# three checks in CI, and governed by the expand-migrate-contract
# discipline. The enforcement record is the CI's word for the same
# dataset: one run row per declared check. The dates are chosen
# relative to the CI anchor date 2026-10-20.
package datacontract.fixture

import rego.v1

today := "2026-10-20"

contract_file := "datacontract.yaml"

enforcement_file := "enforcement.yaml"

contract := {
	"dataset": "payments.settlements",
	"version": 2,
	"reviewedOn": "2026-10-18",
	"owner": "Payments team",
	"schema": {
		"ref": "schemas/settlement-record.schema.json",
		"subject": "one settlement record as captured by the provider webhook",
	},
	"freshness": {
		"slaHours": 24,
	},
	"quality": [
		{"metric": "settlement.completeness", "min": 0.995},
		{"metric": "settlement.schema-mismatch-rate", "max": 0.001},
	],
	"consumers": [
		{"name": "Billing team", "use": "settlement reconciliation"},
		{"name": "Finance reporting", "use": "the nightly revenue roll-up"},
	],
	"enforcement": [
		{"check": "schema-conformance", "pipeline": ".github/workflows/data-contract-checks.yaml"},
		{"check": "freshness-lag", "pipeline": ".github/workflows/data-contract-checks.yaml"},
		{"check": "quality-thresholds", "pipeline": ".github/workflows/data-contract-checks.yaml"},
	],
	"changes": {
		"methodology": "expand-migrate-contract",
		"deprecationWindowDays": 90,
	},
}

enforcement := {
	"dataset": "payments.settlements",
	"version": 1,
	"reviewedOn": "2026-10-19",
	"owner": "Payments team",
	"runs": [
		{"check": "schema-conformance", "ranOn": "2026-10-20"},
		{"check": "freshness-lag", "ranOn": "2026-10-20"},
		{"check": "quality-thresholds", "ranOn": "2026-10-19"},
	],
}

validate_input(contract_doc) := {
	"contract": contract_doc,
	"today": today,
	"contractFile": contract_file,
}

gate_input(contract_doc, evidence_doc) := {
	"contract": contract_doc,
	"enforcement": evidence_doc,
	"today": today,
	"contractFile": contract_file,
	"enforcementFile": enforcement_file,
}

control_input := gate_input(contract, enforcement)

# --- override helpers --------------------------------------------------------
#
# The #69 lesson, applied: an array comprehension with a condition
# in the body filters, so per-element overrides go through explicit
# two-definition helpers that always answer — the row itself when it
# does not match, the patched row when it does.

# Field replacement, not merge: object.union deep-merges object values,
# so a patch that means "this object is now X" removes the key first.
replace_field(obj, patch) := object.union(object.remove(obj, object.keys(patch)), patch)

# Override one top-level field of a document.
with_field(doc, patch) := replace_field(doc, patch)

# Override one field of one quality row, by metric name.
with_quality_field(contract_doc, metric, patch) := object.union(contract_doc, {"quality": [quality_field_override(q, metric, patch) |
	some q in contract_doc.quality
]})

quality_field_override(q, metric, patch) := replace_field(q, patch) if object.get(q, "metric", null) == metric

quality_field_override(q, metric, patch) := q if object.get(q, "metric", null) != metric

# Override one field of one consumer row, by name.
with_consumer_field(contract_doc, name, patch) := object.union(contract_doc, {"consumers": [consumer_field_override(c, name, patch) |
	some c in contract_doc.consumers
]})

consumer_field_override(c, name, patch) := replace_field(c, patch) if object.get(c, "name", null) == name

consumer_field_override(c, name, patch) := c if object.get(c, "name", null) != name

# Override one field of one declared check row, by check name.
with_check_field(contract_doc, check, patch) := object.union(contract_doc, {"enforcement": [check_field_override(c, check, patch) |
	some c in contract_doc.enforcement
]})

check_field_override(c, check, patch) := replace_field(c, patch) if object.get(c, "check", null) == check

check_field_override(c, check, patch) := c if object.get(c, "check", null) != check

# Override one field of one run row, by check name.
with_run_field(evidence_doc, check, patch) := object.union(evidence_doc, {"runs": [run_field_override(r, check, patch) |
	some r in evidence_doc.runs
]})

run_field_override(r, check, patch) := replace_field(r, patch) if object.get(r, "check", null) == check

run_field_override(r, check, patch) := r if object.get(r, "check", null) != check

package datacontract.audit_test

import rego.v1

import data.datacontract

import data.datacontract.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

card(r, item) := c if {
	some c in r.cards
	c.item == item
}

without_run(evidence_doc, name) := object.union(object.remove(evidence_doc, {"runs"}), {"runs": [r |
	some r in evidence_doc.runs
	r.check != name
]})

# --- the control: one audit, the whole answer ---------------------------------

test_control_audit_is_consistent if {
	r := datacontract.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_control_audit_shape if {
	r := datacontract.audit with input as fixture.control_input
	object.keys(r) == {"valid", "findings", "cards", "verdict"}
	count(r.cards) == 3
}

test_control_audit_cards_carry_the_board if {
	r := datacontract.audit with input as fixture.control_input
	card(r, "freshness-lag").area == "checks"
	card(r, "freshness-lag").verdict == "consistent"
}

# --- the composed union: shared conditions report once ------------------------

# The contract's own findings are sets in both analyzers, so a
# contract stamped wrong is reported by the audit exactly once —
# the union deduplicates, not double-counts.
test_audit_reports_an_unversioned_contract_once if {
	c := fixture.with_field(fixture.contract, {"version": null})
	r := datacontract.audit with input as fixture.gate_input(c, fixture.enforcement)
	count([f | some f in r.findings; f.rule == "contract/version-required"]) == 1
	r.verdict == "unreadable"
}

test_audit_reports_a_missing_contract_once if {
	r := datacontract.audit with input as {
		"contract": "not an object",
		"enforcement": fixture.enforcement,
		"today": fixture.today,
	}
	count(r.findings) == 1
	error_rules(r)["contract/missing"]
	r.verdict == "unreadable"
}

test_audit_reports_a_freshness_clause_without_an_sla_once if {
	c := fixture.with_field(fixture.contract, {"freshness": {}})
	r := datacontract.audit with input as fixture.gate_input(c, fixture.enforcement)
	count(r.findings) == 1
	error_rules(r)["freshness/sla-required"]
	r.verdict == "unreadable"
}

test_audit_reports_missing_evidence_with_its_cards if {
	r := datacontract.audit with input as object.remove(fixture.control_input, {"enforcement"})
	not r.valid
	error_rules(r)["evidence/missing"]

	# the three declared checks never ran, and the board says so
	count([f | some f in r.findings; f.rule == "gate/check-never-run"]) == 3
	count(r.cards) == 3
	card(r, "schema-conformance").verdict == "drifts"
	r.verdict == "unreadable"
}

# --- the drifts reach the composed verdict -------------------------------------

test_audit_drifts_when_a_declared_check_never_ran if {
	e := without_run(fixture.enforcement, "quality-thresholds")
	r := datacontract.audit with input as fixture.gate_input(fixture.contract, e)
	count(r.findings) == 1
	error_rules(r)["gate/check-never-run"]
	r.verdict == "drifts"
}

test_audit_drifts_on_the_wrong_dataset if {
	e := fixture.with_field(fixture.enforcement, {"dataset": "risk.exposures"})
	r := datacontract.audit with input as fixture.gate_input(fixture.contract, e)
	count(r.findings) == 1
	error_rules(r)["gate/dataset-mismatch"]
	r.verdict == "drifts"
}

test_audit_drifts_on_an_undeclared_check if {
	e := object.union(object.remove(fixture.enforcement, {"runs"}), {"runs": array.concat(fixture.enforcement.runs, [{"check": "settlement-replay", "ranOn": "2026-10-19"}])})
	r := datacontract.audit with input as fixture.gate_input(fixture.contract, e)
	count(r.findings) == 1
	error_rules(r)["gate/check-undeclared"]
	r.verdict == "drifts"
}

# --- the ladder reaches the audit verdict honestly ------------------------------

test_audit_verdict_is_unreadable_when_the_clock_is_not_a_date if {
	r := datacontract.audit with input as object.union(object.remove(fixture.control_input, {"today"}), {"today": "not a date"})
	not r.valid
	r.verdict == "unreadable"
}

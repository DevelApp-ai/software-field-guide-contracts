package datacontract.gate_test

import rego.v1

import data.datacontract

import data.datacontract.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

card(r, item) := c if {
	some c in r.cards
	c.item == item
}

# --- override helpers -------------------------------------------------------

# Drop every run row that names one check: the record that never
# shows that check running.
without_run(evidence_doc, name) := object.union(object.remove(evidence_doc, {"runs"}), {"runs": [r |
	some r in evidence_doc.runs
	r.check != name
]})

# Append one run row to the record.
with_extra_run(evidence_doc, row) := object.union(object.remove(evidence_doc, {"runs"}), {"runs": array.concat(evidence_doc.runs, [row])})

# --- the control: every declared check shows its run ----------------------------

test_control_gate_passes_and_renders_consistent if {
	r := datacontract.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_control_renders_one_card_per_declared_check if {
	r := datacontract.gate with input as fixture.control_input
	count(r.cards) == 3
	r.cards[0].area == "checks"
}

test_control_card_verdicts_are_all_consistent if {
	r := datacontract.gate with input as fixture.control_input
	count([c | some c in r.cards; c.verdict == "consistent"]) == 3
}

test_control_card_details if {
	r := datacontract.gate with input as fixture.control_input
	card(r, "schema-conformance").detail == "declared, run 2026-10-20 per the enforcement record (datacontract.yaml, enforcement.yaml)"
	card(r, "quality-thresholds").detail == "declared, run 2026-10-19 per the enforcement record (datacontract.yaml, enforcement.yaml)"
}

# --- the three drifts: conformance failures, the gate refuses -----------------

test_check_never_run_fails_the_gate if {
	e := without_run(fixture.enforcement, "quality-thresholds")
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["gate/check-never-run"]
	r.verdict == "drifts"
}

test_check_never_run_bites_exactly_once if {
	e := without_run(fixture.enforcement, "quality-thresholds")
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	count(r.findings) == 1
}

test_check_never_run_cites_both_files if {
	e := without_run(fixture.enforcement, "quality-thresholds")
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	some f in r.findings
	f.rule == "gate/check-never-run"
	contains(f.message, "datacontract.yaml")
	contains(f.message, "enforcement.yaml")
}

test_check_never_run_card_renders_drifts if {
	e := without_run(fixture.enforcement, "quality-thresholds")
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	card(r, "quality-thresholds").verdict == "drifts"
	card(r, "quality-thresholds").detail == "declared, but no run row in the enforcement record names it (datacontract.yaml, enforcement.yaml)"
	card(r, "schema-conformance").verdict == "consistent"
}

test_dataset_mismatch_fails_the_gate if {
	e := fixture.with_field(fixture.enforcement, {"dataset": "risk.exposures"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["gate/dataset-mismatch"]
	r.verdict == "drifts"
}

test_dataset_mismatch_bites_exactly_once if {
	e := fixture.with_field(fixture.enforcement, {"dataset": "risk.exposures"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	count(r.findings) == 1
}

test_dataset_mismatch_cites_both_files if {
	e := fixture.with_field(fixture.enforcement, {"dataset": "risk.exposures"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	some f in r.findings
	f.rule == "gate/dataset-mismatch"
	contains(f.message, "datacontract.yaml")
	contains(f.message, "enforcement.yaml")
}

test_undeclared_check_fails_the_gate if {
	e := with_extra_run(fixture.enforcement, {"check": "settlement-replay", "ranOn": "2026-10-19"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["gate/check-undeclared"]
	r.verdict == "drifts"
}

test_undeclared_check_bites_exactly_once if {
	e := with_extra_run(fixture.enforcement, {"check": "settlement-replay", "ranOn": "2026-10-19"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	count(r.findings) == 1
}

# --- the enforcement record at the gate -------------------------------------------

test_evidence_missing_fails_the_gate if {
	r := datacontract.gate with input as object.remove(fixture.control_input, {"enforcement"})
	not r.valid
	error_rules(r)["evidence/missing"]
	r.verdict == "unreadable"
}

test_evidence_version_required if {
	e := fixture.with_field(fixture.enforcement, {"version": null})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["evidence/version-required"]
	r.verdict == "unreadable"
}

test_evidence_reviewed_on_invalid if {
	e := fixture.with_field(fixture.enforcement, {"reviewedOn": "not a date"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["evidence/reviewed-on-invalid"]
}

test_evidence_reviewed_in_future if {
	e := fixture.with_field(fixture.enforcement, {"reviewedOn": "2026-12-01"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["evidence/reviewed-in-future"]
}

test_evidence_reviewed_stale if {
	e := fixture.with_field(fixture.enforcement, {"reviewedOn": "2024-10-01"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["evidence/reviewed-stale"]
}

test_evidence_owner_required if {
	e := fixture.with_field(fixture.enforcement, {"owner": ""})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["evidence/owner-required"]
}

test_evidence_dataset_required if {
	e := fixture.with_field(fixture.enforcement, {"dataset": ""})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["evidence/dataset-required"]
}

test_evidence_runs_must_be_array if {
	e := fixture.with_field(fixture.enforcement, {"runs": "schema-conformance"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["evidence/runs-must-be-array"]
}

test_evidence_row_must_be_object if {
	e := with_extra_run(fixture.enforcement, "schema-conformance")
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["evidence/row-must-be-object"]
}

test_run_check_required if {
	e := fixture.with_run_field(fixture.enforcement, "schema-conformance", {"check": ""})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["run/check-required"]
}

test_run_ran_on_invalid if {
	e := fixture.with_run_field(fixture.enforcement, "schema-conformance", {"ranOn": "20/10/2026"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["run/ran-on-invalid"]
}

# Evidence dated after today is evidence that has not happened: the
# row is refused, honestly, and never quietly counted.
test_run_ran_in_future if {
	e := fixture.with_run_field(fixture.enforcement, "schema-conformance", {"ranOn": "2026-12-01"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["run/ran-in-future"]
	r.verdict == "unreadable"
}

test_run_duplicate if {
	e := with_extra_run(fixture.enforcement, {"check": "schema-conformance", "ranOn": "2026-10-18"})
	r := datacontract.gate with input as fixture.gate_input(fixture.contract, e)
	not r.valid
	error_rules(r)["run/duplicate"]
}

# --- the gate re-reports the contract's own findings -------------------------------

test_gate_fails_on_an_unversioned_contract if {
	c := fixture.with_field(fixture.contract, {"version": null})
	r := datacontract.gate with input as fixture.gate_input(c, fixture.enforcement)
	not r.valid
	error_rules(r)["contract/version-required"]
	r.verdict == "unreadable"
}

test_gate_fails_on_a_contract_it_cannot_read_at_all if {
	r := datacontract.gate with input as {
		"contract": "not an object",
		"enforcement": fixture.enforcement,
		"today": fixture.today,
	}
	not r.valid
	error_rules(r)["contract/missing"]
	r.verdict == "unreadable"
}

test_gate_fails_on_a_freshness_clause_without_an_sla if {
	c := fixture.with_field(fixture.contract, {"freshness": {}})
	r := datacontract.gate with input as fixture.gate_input(c, fixture.enforcement)
	not r.valid
	error_rules(r)["freshness/sla-required"]
}

package compliance.audit_test

import rego.v1

import data.compliance

import data.compliance.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the composed audit: one evaluation, the whole answer -----------------------

test_control_audit_is_consistent_with_the_requirement_cards if {
	r := compliance.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
	count(r.requirements) == 4
}

test_audit_answers_in_the_stable_shape if {
	r := compliance.audit with input as fixture.control_input
	object.keys(r) == {"findings", "requirements", "valid", "verdict"}
}

test_audit_composes_both_analyzers if {
	# one manifest-side failure (a control whose review clock lapsed)
	# and one join failure (a requirement nobody controls) answer in
	# one evaluation — the playground renders both from a single
	# verdict
	catalog := fixture.with_requirement(fixture.requirements_catalog, {"id": "ISO-27001-A.5.1", "title": "Access rights are subject to an access control policy", "source": "ISO/IEC 27001 A.5.1"})
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-04", {"reviewedOn": "2026-08-15", "intervalDays": 30})
	r := compliance.audit with input as fixture.gate_input(m, catalog)
	not r.valid
	r.verdict == "drifts"
	error_rules(r)["gate/requirement-unmapped"]
	error_rules(r)["gate/review-expired"]
}

# The findings of the two analyzers are sets: a shared condition is
# reported once, not twice.
test_audit_reports_the_shared_condition_once if {
	r := compliance.audit with input as {"requirements": fixture.requirements_catalog, "today": fixture.today}
	not r.valid
	count([f | some f in r.findings; f.rule == "controls/missing"]) == 1
	count([f | some f in r.findings; f.rule == "input/invalid"]) == 0
	r.verdict == "unreadable"
}

test_audit_is_deterministic if {
	a := compliance.audit with input as fixture.control_input
	b := compliance.audit with input as fixture.control_input
	a == b
}

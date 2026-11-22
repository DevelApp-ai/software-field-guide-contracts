package lifecycle.audit_test

import rego.v1

import data.lifecycle

import data.lifecycle.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the composed audit: one evaluation, the whole answer -----------------------

test_control_audit_is_consistent_with_the_transition_cards if {
	r := lifecycle.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
	count(r.transitions) == 3
}

test_audit_refuses_a_component_mismatch if {
	m := fixture.with_field(fixture.record_doc, {"component": "storefront-theme"})
	r := lifecycle.audit with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["gate/component-mismatch"]
	r.verdict == "drifts"
}

# The findings of the two analyzers are sets: a shared condition is
# reported once, not twice.
test_audit_reports_a_broken_record_once if {
	m := fixture.with_field(fixture.record_doc, {"version": null})
	r := lifecycle.audit with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	count([f | some f in r.findings; f.rule == "lifecycle/version-required"]) == 1
	r.verdict == "unreadable"
}

test_audit_reports_missing_documents_once if {
	r := lifecycle.audit with input as {"today": fixture.today}
	count([f | some f in r.findings; f.rule == "package/missing"]) == 1
	count([f | some f in r.findings; f.rule == "lifecycle/missing"]) == 1
	count([f | some f in r.findings; f.rule == "input/invalid"]) == 0
	r.verdict == "unreadable"
}

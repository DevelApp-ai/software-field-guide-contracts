package matrix.audit_test

import rego.v1

import data.matrix

import data.matrix.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the composed audit: one evaluation, the whole answer -----------------------

test_control_audit_is_consistent_with_the_fabric_cards if {
	r := matrix.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
	count(r.fabrics) == 3
}

test_audit_refuses_a_version_skew if {
	m := fixture.with_render_field(fixture.matrix_doc, "aws-eu-central", {"version": "1.3.0"})
	r := matrix.audit with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["gate/render-version-skew"]
	r.verdict == "drifts"
}

# The findings of the two analyzers are sets: a shared condition is
# reported once, not twice.
test_audit_reports_a_broken_matrix_once if {
	m := fixture.with_field(fixture.matrix_doc, {"version": null})
	r := matrix.audit with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	count([f | some f in r.findings; f.rule == "matrix/version-required"]) == 1
	r.verdict == "unreadable"
}

test_audit_reports_missing_documents_once if {
	r := matrix.audit with input as {"today": fixture.today}
	count([f | some f in r.findings; f.rule == "package/missing"]) == 1
	count([f | some f in r.findings; f.rule == "matrix/missing"]) == 1
	count([f | some f in r.findings; f.rule == "input/invalid"]) == 0
	r.verdict == "unreadable"
}

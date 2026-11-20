package policy.audit_test

import rego.v1

import data.policy

import data.policy.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the composed shape: one verdict, one findings list, the board --------

test_audit_control_is_consistent if {
	r := policy.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_audit_control_renders_the_board if {
	r := policy.audit with input as fixture.control_input
	count(r.policies) == 2
	r.policies[0].policy == "pci-scan"
	r.policies[0].verdict == "consistent"
	r.policies[1].policy == "tier-egress"
	r.policies[1].verdict == "consistent"
}

# The audit dedupes: a shared condition is the same set member in
# both analyzers, so it is reported once, not twice.
test_audit_reports_a_missing_catalog_once if {
	r := policy.audit with input as {
		"package": fixture.package_manifest,
		"today": fixture.today,
	}
	not r.valid
	count([f | some f in r.findings; f.rule == "input/invalid"]) == 0
	count([f | some f in r.findings; f.rule == "catalog/missing"]) == 1
	r.verdict == "unreadable"
}

test_audit_bites_once_on_a_broken_row if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"signature": null})
	r := policy.audit with input as fixture.gate_input(c, fixture.package_manifest)
	not r.valid
	error_rules(r)["policy/signature-required"]
	count([f | some f in r.findings; f.rule == "policy/signature-required"]) == 1
	r.verdict == "unreadable"
}

# Unreadable outranks drift: a catalog nobody can read plus a
# binding that drifts is a question the gate refuses to answer,
# honestly.
test_audit_unreadable_outranks_drift if {
	c := fixture.with_catalog_row_field(fixture.catalog, "tier-egress", {"posture": "sometimes"})
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"path": "/policies/tier-egress-v2.rego"})
	r := policy.audit with input as fixture.gate_input(c, p)
	not r.valid
	error_rules(r)["policy/posture-unknown"]
	error_rules(r)["gate/binding-path-drift"]
	r.verdict == "unreadable"
}

test_audit_drifts_when_only_the_join_drifts if {
	c := fixture.without_catalog_row(fixture.catalog, "tier-egress")
	r := policy.audit with input as fixture.gate_input(c, fixture.package_manifest)
	not r.valid
	error_rules(r)["gate/policy-unresolved"]
	r.verdict == "drifts"
	count([f | some f in r.findings; startswith(f.rule, "gate/")]) == 1
}

package policy.gate_test

import rego.v1

import data.policy

import data.policy.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

card(r, name) := c if {
	some c in r.policies
	c.policy == name
}

# --- the control: two bound policies, both answering the catalog ----------------

test_control_gate_passes_and_renders_consistent if {
	r := policy.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

# The board is one card per BOUND policy: the third, unbound catalog
# row is a policy available to other packages, not a drift.
test_control_renders_one_card_per_bound_policy if {
	r := policy.gate with input as fixture.control_input
	count(r.policies) == 2
	r.policies[0].policy == "pci-scan"
	r.policies[1].policy == "tier-egress"
}

test_control_card_verdicts_are_all_consistent if {
	r := policy.gate with input as fixture.control_input
	count([c | some c in r.policies; c.verdict == "consistent"]) == 2
}

test_control_card_details if {
	r := policy.gate with input as fixture.control_input
	card(r, "pci-scan").detail == "bound at the catalog's exact path '/policies/pci-scan.rego', posture 'enforce' on the ladder (package.yaml, catalog.yaml)"
	card(r, "tier-egress").detail == "bound at the catalog's exact path '/policies/tier-egress.rego', posture 'enforce' on the ladder (package.yaml, catalog.yaml)"
}

# The unbound catalog row is NOT flagged: the shared catalog is
# judged at the join, not by inventory.
test_unbound_catalog_row_is_not_a_drift if {
	r := policy.gate with input as fixture.control_input
	count([f | some f in r.findings; contains(f.message, "allowed-regions")]) == 0
	count(r.findings) == 0
}

# --- the two drifts: conformance failures, the gate refuses -----------------

test_unresolved_binding_fails_the_gate if {
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"policy": "tier-egress-v2"})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	not r.valid
	error_rules(r)["gate/policy-unresolved"]
	r.verdict == "drifts"
}

test_unresolved_binding_cites_both_files if {
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"policy": "ghost-scan"})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	some f in r.findings
	f.rule == "gate/policy-unresolved"
	contains(f.message, "package.yaml")
	contains(f.message, "catalog.yaml")
}

test_unresolved_binding_renders_the_card_drifts if {
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"policy": "ghost-scan"})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	card(r, "ghost-scan").verdict == "drifts"
}

# A catalog with one row removed: the binding is judged against
# the platform's only word, and that word is silent.
test_missing_catalog_row_fails_the_gate if {
	c := fixture.without_catalog_row(fixture.catalog, "tier-egress")
	r := policy.gate with input as fixture.gate_input(c, fixture.package_manifest)
	not r.valid
	error_rules(r)["gate/policy-unresolved"]
	r.verdict == "drifts"
}

test_binding_path_drift_fails_the_gate if {
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"path": "/policies/tier-egress-v2.rego"})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	not r.valid
	error_rules(r)["gate/binding-path-drift"]
	r.verdict == "drifts"
}

test_binding_path_drift_bites_exactly_once_at_the_join if {
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"path": "/policies/tier-egress-v2.rego"})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	count([f | some f in r.findings; startswith(f.rule, "gate/")]) == 1
}

test_binding_path_drift_cites_both_files if {
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"path": "/policies/tier-egress-v2.rego"})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	some f in r.findings
	f.rule == "gate/binding-path-drift"
	contains(f.message, "package.yaml")
	contains(f.message, "catalog.yaml")
}

test_binding_path_drift_card_names_both_paths if {
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"path": "/policies/tier-egress-v2.rego"})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	card(r, "tier-egress").verdict == "drifts"
	contains(card(r, "tier-egress").detail, "/policies/tier-egress-v2.rego")
	contains(card(r, "tier-egress").detail, "/policies/tier-egress.rego")
}

# The path drift can be fixed from either side: re-pointing the
# catalog is the same pair agreement, differently broken.
test_catalog_path_change_drifts_the_binding if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"path": "/policies/pci-scan-renewed.rego"})
	r := policy.gate with input as fixture.gate_input(c, fixture.package_manifest)
	not r.valid
	error_rules(r)["gate/binding-path-drift"]
}

# --- the package at the gate: only what the join reads -----------------------

test_gate_fails_on_a_package_it_cannot_read_at_all if {
	r := policy.gate with input as {
		"catalog": fixture.catalog,
		"package": "not an object",
		"today": fixture.today,
	}
	not r.valid
	error_rules(r)["package/missing"]
	r.verdict == "unreadable"
	count(r.policies) == 0
}

test_package_bindings_must_be_array if {
	p := fixture.with_field(fixture.package_manifest, {"policyBindings": "pci-scan"})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	not r.valid
	error_rules(r)["package/bindings-must-be-array"]
}

test_package_binding_must_be_object if {
	p := fixture.with_field(fixture.package_manifest, {"policyBindings": ["pci-scan"]})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	not r.valid
	error_rules(r)["package/binding-must-be-object"]
}

test_package_binding_policy_required if {
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"policy": null})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	not r.valid
	error_rules(r)["package/binding-policy-required"]
}

test_package_binding_path_required if {
	p := fixture.with_binding_field(fixture.package_manifest, "tier-egress", {"path": null})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	not r.valid
	error_rules(r)["package/binding-path-required"]
}

# The exactness gap the component validator (#101) never checked: a
# present-and-exact-shaped binding whose path is a glob. The join
# refuses to guess.
test_package_binding_path_glob if {
	p := fixture.with_binding_field(fixture.package_manifest, "pci-scan", {"path": "/policies/pci-*.rego"})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	not r.valid
	error_rules(r)["package/binding-path-glob"]
	r.verdict == "unreadable"
}

test_package_binding_duplicate if {
	p := fixture.with_field(fixture.package_manifest, {"policyBindings": array.concat(fixture.package_manifest.policyBindings, [{"policy": "pci-scan", "path": "/policies/pci-scan-alt.rego"}])})
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	not r.valid
	error_rules(r)["package/binding-duplicate"]
}

# The absent bindings are honest: a package binding no policies
# judges consistently — there is simply nothing in force to check.
test_bindings_absent_is_consistent_and_renders_no_cards if {
	p := fixture.without_bindings(fixture.package_manifest)
	r := policy.gate with input as fixture.gate_input(fixture.catalog, p)
	r.valid == true
	r.verdict == "consistent"
	count(r.findings) == 0
	count(r.policies) == 0
}

# --- the gate re-reports the catalog's own findings --------------------------

test_gate_fails_on_a_stale_catalog if {
	c := fixture.with_field(fixture.catalog, {"reviewedOn": "2024-10-01"})
	r := policy.gate with input as fixture.gate_input(c, fixture.package_manifest)
	not r.valid
	error_rules(r)["catalog/reviewed-stale"]
	r.verdict == "unreadable"
}

test_gate_fails_on_an_unreadable_catalog_row if {
	c := fixture.with_catalog_row_field(fixture.catalog, "tier-egress", {"digest": "deadbeef"})
	r := policy.gate with input as fixture.gate_input(c, fixture.package_manifest)
	not r.valid
	error_rules(r)["policy/digest-malformed"]
	r.verdict == "unreadable"
}

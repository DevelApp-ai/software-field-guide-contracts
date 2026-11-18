package matrix.gate_test

import rego.v1

import data.matrix

import data.matrix.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

card(r, fabric) := c if {
	some c in r.fabrics
	c.fabric == fabric
}

# --- the control: one package, three fabrics, all agreeing ---------------------

test_control_gate_passes_and_renders_consistent if {
	r := matrix.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_control_renders_one_card_per_declared_fabric if {
	r := matrix.gate with input as fixture.control_input
	{c.fabric | some c in r.fabrics} == {"azure-west-europe", "aws-eu-central", "onprem-vsphere"}
}

test_control_card_verdicts_are_all_consistent if {
	r := matrix.gate with input as fixture.control_input
	count([c | some c in r.fabrics; c.verdict == "consistent"]) == 3
}

test_control_card_detail_names_what_agrees if {
	r := matrix.gate with input as fixture.control_input
	card(r, "azure-west-europe").detail == "renders v1.4.0 at the manifest's digest with 2 declared policy binding(s) in force (matrix.yaml, package.yaml)"
}

# --- the six drifts: consistency failures, the gate refuses ----------------------

test_version_skew_fails_the_gate if {
	m := fixture.with_render_field(fixture.matrix_doc, "aws-eu-central", {"version": "1.3.0"})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["gate/render-version-skew"]
	r.verdict == "drifts"
}

test_version_skew_cites_the_fabric_and_both_files if {
	m := fixture.with_render_field(fixture.matrix_doc, "aws-eu-central", {"version": "1.3.0"})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	some f in r.findings
	f.rule == "gate/render-version-skew"
	contains(f.message, "aws-eu-central")
	contains(f.message, "1.3.0")
	contains(f.message, "package.yaml")
	contains(f.message, "matrix.yaml")
}

test_version_skew_card_names_the_divergent_field if {
	m := fixture.with_render_field(fixture.matrix_doc, "aws-eu-central", {"version": "1.3.0"})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	card(r, "aws-eu-central").verdict == "drifts"
	card(r, "aws-eu-central").detail == "renders v1.3.0 against the manifest's v1.4.0 (matrix.yaml, package.yaml)"
	card(r, "azure-west-europe").verdict == "consistent"
}

test_digest_drift_fails_the_gate if {
	m := fixture.with_render_field(fixture.matrix_doc, "onprem-vsphere", {"digest": "4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80"})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["gate/render-digest-drift"]
	r.verdict == "drifts"
}

test_binding_missing_from_one_fabric_fails_the_gate if {
	m := fixture.with_render_bindings(fixture.matrix_doc, "onprem-vsphere", [{"policy": "pci-scan", "path": "/policies/pci-scan.rego"}])
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["gate/binding-missing"]
	r.verdict == "drifts"
}

test_binding_present_in_one_fabric_only_bites_per_missing_fabric if {
	m1 := fixture.with_render_bindings(fixture.matrix_doc, "aws-eu-central", [{"policy": "pci-scan", "path": "/policies/pci-scan.rego"}])
	m := fixture.with_render_bindings(m1, "onprem-vsphere", [{"policy": "pci-scan", "path": "/policies/pci-scan.rego"}])
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	bites := count([f | some f in r.findings; f.rule == "gate/binding-missing"])
	bites == 2
	some f1 in r.findings
	f1.rule == "gate/binding-missing"
	contains(f1.message, "aws-eu-central")
	some f2 in r.findings
	f2.rule == "gate/binding-missing"
	contains(f2.message, "onprem-vsphere")
}

test_binding_undeclared_fails_the_gate if {
	m := fixture.with_binding_field(fixture.matrix_doc, "azure-west-europe", "pci-scan", {"policy": "shadow-scan"})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["gate/binding-undeclared"]
	r.verdict == "drifts"
}

test_a_binding_at_a_different_path_disagrees_both_ways if {
	m := fixture.with_binding_field(fixture.matrix_doc, "azure-west-europe", "pci-scan", {"path": "/policies/pci-scan-v2.rego"})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	error_rules(r)["gate/binding-missing"]
	error_rules(r)["gate/binding-undeclared"]
}

test_unrendered_fabric_fails_the_gate if {
	m := fixture.without_render(fixture.matrix_doc, "onprem-vsphere")
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["gate/fabric-unrendered"]
	r.verdict == "drifts"
}

test_unrendered_fabric_card_says_so if {
	m := fixture.without_render(fixture.matrix_doc, "onprem-vsphere")
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	card(r, "onprem-vsphere").verdict == "drifts"
	card(r, "onprem-vsphere").detail == "no render row: coverage claimed and never delivered (matrix.yaml)"
}

test_component_mismatch_fails_the_gate if {
	m := fixture.with_field(fixture.matrix_doc, {"component": "storefront-theme"})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["gate/component-mismatch"]
	r.verdict == "drifts"
}

test_component_mismatch_cites_both_documents if {
	m := fixture.with_field(fixture.matrix_doc, {"component": "storefront-theme"})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	some f in r.findings
	f.rule == "gate/component-mismatch"
	contains(f.message, "storefront-theme")
	contains(f.message, "payments-checkout")
	contains(f.message, "package.yaml")
	contains(f.message, "matrix.yaml")
}

# A package that declares no policy bindings is honest, not broken:
# every fabric's renders then agree by holding none in force.
test_no_declared_bindings_and_none_rendered_is_consistent if {
	p := object.remove(fixture.package_manifest, {"policyBindings"})
	m := fixture.with_render_bindings(fixture.with_render_bindings(fixture.with_render_bindings(fixture.matrix_doc, "azure-west-europe", []), "aws-eu-central", []), "onprem-vsphere", [])
	r := matrix.gate with input as fixture.gate_input(p, m)
	r.valid == true
	r.verdict == "consistent"
}

# --- the package manifest at the gate -----------------------------------------------

test_package_missing_fails_the_gate if {
	r := matrix.gate with input as object.remove(fixture.control_input, {"package"})
	not r.valid
	error_rules(r)["package/missing"]
	r.verdict == "unreadable"
}

test_package_version_required_at_the_gate if {
	p := fixture.with_field(fixture.package_manifest, {"version": null})
	r := matrix.gate with input as fixture.gate_input(p, fixture.matrix_doc)
	not r.valid
	error_rules(r)["package/version-required"]
	r.verdict == "unreadable"
}

test_package_digest_malformed_at_the_gate if {
	p := fixture.with_field(fixture.package_manifest, {"artifactDigest": "deadbeef"})
	r := matrix.gate with input as fixture.gate_input(p, fixture.matrix_doc)
	not r.valid
	error_rules(r)["artifact/digest-malformed"]
	r.verdict == "unreadable"
}

test_package_bindings_must_be_array if {
	p := fixture.with_field(fixture.package_manifest, {"policyBindings": "pci-scan"})
	r := matrix.gate with input as fixture.gate_input(p, fixture.matrix_doc)
	not r.valid
	error_rules(r)["package/bindings-must-be-array"]
	r.verdict == "unreadable"
}

test_package_binding_duplicate if {
	p := fixture.with_field(fixture.package_manifest, {"policyBindings": array.concat(fixture.package_manifest.policyBindings, [{"policy": "pci-scan", "path": "/policies/pci-scan-old.rego"}])})
	r := matrix.gate with input as fixture.gate_input(p, fixture.matrix_doc)
	not r.valid
	error_rules(r)["package/binding-duplicate"]
	r.verdict == "unreadable"
}

# --- the gate re-reports the matrix document's own findings --------------------------

test_gate_fails_on_a_matrix_it_cannot_read_at_all if {
	r := matrix.gate with input as {
		"package": fixture.package_manifest,
		"matrix": "not an object",
		"today": fixture.today,
	}
	not r.valid
	error_rules(r)["matrix/missing"]
	r.verdict == "unreadable"
}

test_gate_fails_on_a_stale_matrix if {
	m := fixture.with_field(fixture.matrix_doc, {"reviewedOn": "2024-10-01"})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["matrix/reviewed-stale"]
	r.verdict == "unreadable"
}

test_gate_fails_on_a_undeclared_fabric_row if {
	m := fixture.with_field(fixture.matrix_doc, {"fabrics": ["azure-west-europe", "onprem-vsphere"]})
	r := matrix.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["render/fabric-undeclared"]
	r.verdict == "unreadable"
}

# The board renders only when the join can be asked at all: with no
# package manifest there is nothing to agree with, so no card
# pretends the fabrics agreed.
test_cards_render_only_when_the_join_can_be_asked if {
	r := matrix.gate with input as object.remove(fixture.control_input, {"package"})
	count(r.fabrics) == 0
	r.verdict == "unreadable"
}

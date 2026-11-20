package matrix.policy_test

import rego.v1

import data.matrix

import data.matrix.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the control: the render matrix validates alone ----------------------------

test_control_matrix_validates if {
	r := matrix.validate with input as fixture.validate_input(fixture.matrix_doc)
	r.valid == true
	count(r.findings) == 0
}

# --- the input and the clock -----------------------------------------------------

test_input_invalid if {
	r := matrix.validate with input as "not an object"
	not r.valid
	error_rules(r)["input/invalid"]
}

test_today_invalid if {
	i := object.union(fixture.validate_input(fixture.matrix_doc), {"today": "2026-13-01"})
	r := matrix.validate with input as i
	not r.valid
	error_rules(r)["input/today-invalid"]
}

# --- the matrix document is missing --------------------------------------------

test_matrix_missing if {
	r := matrix.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["matrix/missing"]
}

# --- the matrix stamps ------------------------------------------------------------

test_matrix_version_required if {
	m := fixture.with_field(fixture.matrix_doc, {"version": null})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["matrix/version-required"]
}

test_matrix_reviewed_on_invalid if {
	m := fixture.with_field(fixture.matrix_doc, {"reviewedOn": "2026-02-30"})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["matrix/reviewed-on-invalid"]
}

test_matrix_reviewed_in_future if {
	m := fixture.with_field(fixture.matrix_doc, {"reviewedOn": "2026-12-01"})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["matrix/reviewed-in-future"]
}

test_matrix_reviewed_stale if {
	m := fixture.with_field(fixture.matrix_doc, {"reviewedOn": "2024-10-01"})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["matrix/reviewed-stale"]
}

test_matrix_owner_required if {
	m := fixture.with_field(fixture.matrix_doc, {"owner": " "})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["matrix/owner-required"]
}

test_matrix_component_required if {
	m := fixture.with_field(fixture.matrix_doc, {"component": ""})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["matrix/component-required"]
}

# --- the declared fabrics -----------------------------------------------------------

test_fabrics_must_be_array if {
	m := fixture.with_field(fixture.matrix_doc, {"fabrics": "azure-west-europe"})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["fabrics/must-be-array"]
}

test_fabrics_required if {
	m := fixture.with_field(fixture.matrix_doc, {"fabrics": []})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["fabrics/required"]
}

test_fabric_name_required if {
	m := fixture.with_field(fixture.matrix_doc, {"fabrics": ["azure-west-europe", ""]})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["fabric/name-required"]
}

test_fabric_name_duplicate if {
	m := fixture.with_field(fixture.matrix_doc, {"fabrics": ["azure-west-europe", "azure-west-europe", "aws-eu-central", "onprem-vsphere"]})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["fabric/name-duplicate"]
}

# --- the render rows ------------------------------------------------------------------

test_renders_must_be_array if {
	m := fixture.with_field(fixture.matrix_doc, {"renders": {"fabric": "azure-west-europe"}})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["renders/must-be-array"]
}

test_renders_rows_required if {
	m := fixture.with_field(fixture.matrix_doc, {"renders": []})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["renders/rows-required"]
}

test_render_row_must_be_object if {
	m := fixture.with_field(fixture.matrix_doc, {"renders": array.concat(["azure-west-europe"], fixture.matrix_doc.renders)})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["renders/row-must-be-object"]
}

test_render_row_invalid_without_a_digest if {
	m := fixture.with_render_field(fixture.matrix_doc, "aws-eu-central", {"digest": "not-a-digest"})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["render/row-invalid"]
}

test_render_fabric_undeclared if {
	m := fixture.with_field(fixture.matrix_doc, {"fabrics": ["azure-west-europe", "onprem-vsphere"]})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["render/fabric-undeclared"]
}

test_render_row_duplicate if {
	m := fixture.with_field(fixture.matrix_doc, {"renders": array.concat(fixture.matrix_doc.renders, [fixture.matrix_doc.renders[0]])})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["render/row-duplicate"]
}

# --- the rendered policy bindings -----------------------------------------------------

test_render_binding_must_be_object if {
	m := fixture.with_render_bindings(fixture.matrix_doc, "onprem-vsphere", ["pci-scan"])
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["render/binding-must-be-object"]
}

test_render_binding_policy_required if {
	m := fixture.with_binding_field(fixture.matrix_doc, "onprem-vsphere", "tier-egress", {"policy": ""})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["render/binding-policy-required"]
}

test_render_binding_path_required if {
	m := fixture.with_binding_field(fixture.matrix_doc, "onprem-vsphere", "tier-egress", {"path": " "})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["render/binding-path-required"]
}

test_render_binding_duplicate if {
	m := fixture.with_binding_field(fixture.matrix_doc, "onprem-vsphere", "tier-egress", {"policy": "pci-scan", "path": "/policies/pci-scan.rego"})
	r := matrix.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["render/binding-duplicate"]
}

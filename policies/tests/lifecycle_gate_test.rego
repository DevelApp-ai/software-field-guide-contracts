package lifecycle.gate_test

import rego.v1

import data.lifecycle

import data.lifecycle.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

card(r, kind) := c if {
	some c in r.transitions
	c.type == kind
}

# --- the control: one package, three transitions, all evidenced -----------------

test_control_gate_passes_and_renders_consistent if {
	r := lifecycle.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_control_renders_one_card_per_recorded_transition if {
	r := lifecycle.gate with input as fixture.control_input
	{c.type | some c in r.transitions} == {"bake", "patch", "upgrade"}
}

test_control_card_verdicts_are_all_consistent if {
	r := lifecycle.gate with input as fixture.control_input
	count([c | some c in r.transitions; c.verdict == "consistent"]) == 3
}

test_control_card_detail_names_what_agrees if {
	r := lifecycle.gate with input as fixture.control_input
	card(r, "bake").detail == "bake recorded 2026-09-30 at the image digest 5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c, evidenced (lifecycle.yaml, package.yaml)"
}

# --- the one drift: the mismatched join, the gate refuses -------------------------

test_component_mismatch_fails_the_gate if {
	m := fixture.with_field(fixture.record_doc, {"component": "storefront-theme"})
	r := lifecycle.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["gate/component-mismatch"]
	r.verdict == "drifts"
}

test_component_mismatch_cites_both_documents if {
	m := fixture.with_field(fixture.record_doc, {"component": "storefront-theme"})
	r := lifecycle.gate with input as fixture.gate_input(fixture.package_manifest, m)
	some f in r.findings
	f.rule == "gate/component-mismatch"
	contains(f.message, "storefront-theme")
	contains(f.message, "payments-checkout")
	contains(f.message, "package.yaml")
	contains(f.message, "lifecycle.yaml")
}

test_component_mismatch_card_names_the_divergence if {
	m := fixture.with_field(fixture.record_doc, {"component": "storefront-theme"})
	r := lifecycle.gate with input as fixture.gate_input(fixture.package_manifest, m)
	card(r, "bake").verdict == "drifts"
	card(r, "bake").detail == "the record documents 'storefront-theme', but the package manifest packages 'payments-checkout' (lifecycle.yaml, package.yaml)"
}

# --- the package manifest at the gate ----------------------------------------------

test_package_missing_fails_the_gate if {
	r := lifecycle.gate with input as object.remove(fixture.control_input, {"package"})
	not r.valid
	error_rules(r)["package/missing"]
	r.verdict == "unreadable"
}

test_package_component_required_at_the_gate if {
	p := fixture.with_field(fixture.package_manifest, {"component": null})
	r := lifecycle.gate with input as fixture.gate_input(p, fixture.record_doc)
	not r.valid
	error_rules(r)["component/name-required"]
	r.verdict == "unreadable"
}

# --- the gate re-reports the record's own findings ------------------------------------

test_gate_fails_on_a_record_it_cannot_read_at_all if {
	r := lifecycle.gate with input as {
		"package": fixture.package_manifest,
		"lifecycle": "not an object",
		"today": fixture.today,
	}
	not r.valid
	error_rules(r)["lifecycle/missing"]
	r.verdict == "unreadable"
}

test_gate_fails_on_a_transition_without_its_evidence if {
	m := fixture.with_transition_field(fixture.record_doc, "bake", {"imageDigest": null})
	r := lifecycle.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["transition/bake-digest-required"]
	r.verdict == "unreadable"
}

test_gate_fails_on_a_stale_record if {
	m := fixture.with_field(fixture.record_doc, {"reviewedOn": "2024-10-01"})
	r := lifecycle.gate with input as fixture.gate_input(fixture.package_manifest, m)
	not r.valid
	error_rules(r)["lifecycle/reviewed-stale"]
	r.verdict == "unreadable"
}

# The board renders only when the join can be asked at all: with no
# package manifest there is nothing to agree with, so no card
# pretends the transitions agreed.
test_cards_render_only_when_the_join_can_be_asked if {
	r := lifecycle.gate with input as object.remove(fixture.control_input, {"package"})
	count(r.transitions) == 0
	r.verdict == "unreadable"
}

package citizen.gate_test

import rego.v1

import data.citizen

import data.citizen.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

advisory_rules(r) := {f.rule | some f in r.findings; f.severity == "advisory"}

card(r, area, item) := c if {
	some c in r.cards
	c.area == area
	c.item == item
}

# --- the control: one app on its rails, everything aligned ----------------------

test_control_gate_passes_and_renders_aligned if {
	r := citizen.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "aligned"
}

test_control_renders_eight_cards_in_fixed_area_order if {
	r := citizen.gate with input as fixture.control_input
	count(r.cards) == 8
	r.cards[0].area == "data bindings"
	r.cards[1].area == "data bindings"
	r.cards[2].area == "actions"
	r.cards[3].area == "actions"
	r.cards[4].area == "spec coverage"
	r.cards[5].area == "spec coverage"
	r.cards[6].area == "guardrails"
	r.cards[7].area == "guardrails"
}

test_control_cards_are_sorted_inside_each_area if {
	r := citizen.gate with input as fixture.control_input
	r.cards[0].item == "audit-log"
	r.cards[1].item == "claims-store"
	r.cards[2].item == "expense.approve"
	r.cards[3].item == "expense.submit"
	r.cards[4].item == "claim-rules"
	r.cards[5].item == "claim-form"
	r.cards[6].item == "action-guardrail"
	r.cards[7].item == "data-guardrail"
}

test_control_card_verdicts_are_all_aligned if {
	r := citizen.gate with input as fixture.control_input
	count([c | some c in r.cards; c.verdict == "aligned"]) == 8
}

test_control_card_details if {
	r := citizen.gate with input as fixture.control_input
	card(r, "data bindings", "claims-store").detail == "rides 'platform-data-api', a rail the registry declares (manifest.yaml)"
	card(r, "actions", "expense.approve").detail == "a rail the spec grants (spec.yaml)"
	card(r, "spec coverage", "claim-form").detail == "behavior 'submits an expense claim' is covered by the spec (spec.yaml)"
	card(r, "guardrails", "data-guardrail").detail == "v3, at or above the platform floor (guardrails.yaml)"
}

# --- the four drifts: advisories, the gate stays green ---------------------------

test_escape_hatch_is_an_advisory_not_an_error if {
	m := fixture.with_binding_field(fixture.manifest, "audit-log", {"via": "raw-sql"})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.valid == true
	r.verdict == "advises changes"
	count([f | some f in r.findings; f.severity == "advisory"]) == 1
	advisory_rules(r)["binding/escape-hatch"]
}

test_escape_hatch_finding_cites_both_files if {
	m := fixture.with_binding_field(fixture.manifest, "audit-log", {"via": "raw-sql"})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	some f in r.findings
	f.rule == "binding/escape-hatch"
	contains(f.message, "manifest.yaml")
	contains(f.message, "guardrails.yaml")
}

test_escape_hatch_card_renders_advises if {
	m := fixture.with_binding_field(fixture.manifest, "audit-log", {"via": "raw-sql"})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	card(r, "data bindings", "audit-log").verdict == "advises"
	card(r, "data bindings", "audit-log").detail == "goes around the rails via 'raw-sql': the platform cannot see this traffic (manifest.yaml)"
}

test_action_outside_the_rails_is_an_advisory if {
	m := fixture.with_field(fixture.manifest, {"actions": array.concat(fixture.manifest.actions, ["expense.purge"])})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.valid == true
	r.verdict == "advises changes"
	count([f | some f in r.findings; f.severity == "advisory"]) == 1
	advisory_rules(r)["action/outside-rails"]
}

test_action_outside_the_rails_cites_both_files if {
	m := fixture.with_field(fixture.manifest, {"actions": array.concat(fixture.manifest.actions, ["expense.purge"])})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	some f in r.findings
	f.rule == "action/outside-rails"
	contains(f.message, "manifest.yaml")
	contains(f.message, "spec.yaml")
}

test_uncovered_behavior_is_an_advisory if {
	m := fixture.with_component_field(fixture.manifest, "claim-rules", {"behavior": "deletes old claims"})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.valid == true
	r.verdict == "advises changes"
	count([f | some f in r.findings; f.severity == "advisory"]) == 1
	advisory_rules(r)["behavior/uncovered-by-spec"]
}

test_uncovered_behavior_card_renders_advises if {
	m := fixture.with_component_field(fixture.manifest, "claim-rules", {"behavior": "deletes old claims"})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	card(r, "spec coverage", "claim-rules").verdict == "advises"
	card(r, "spec coverage", "claim-rules").detail == "behavior 'deletes old claims' is not in the spec's coverage: nobody agreed to it (spec.yaml)"
}

test_guardrail_below_the_floor_is_an_advisory if {
	m := fixture.with_guardrail_field(fixture.manifest, "data-guardrail", {"version": 2})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.valid == true
	r.verdict == "advises changes"
	count([f | some f in r.findings; f.severity == "advisory"]) == 1
	advisory_rules(r)["guardrail/below-floor"]
}

test_guardrail_below_the_floor_names_the_floor if {
	m := fixture.with_guardrail_field(fixture.manifest, "data-guardrail", {"version": 2})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	some f in r.findings
	f.rule == "guardrail/below-floor"
	contains(f.message, "below the platform floor 3")
}

test_guardrail_at_the_floor_is_aligned if {
	m := fixture.with_guardrail_field(fixture.manifest, "data-guardrail", {"version": 3})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.verdict == "aligned"
	count(r.findings) == 0
}

test_unknown_guardrail_is_an_advisory if {
	m := fixture.with_guardrail_field(fixture.manifest, "data-guardrail", {"name": "audit-guardrail"})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.valid == true
	r.verdict == "advises changes"
	advisory_rules(r)["guardrail/unknown"]
}

test_unknown_guardrail_card_names_the_promise if {
	m := fixture.with_guardrail_field(fixture.manifest, "data-guardrail", {"name": "audit-guardrail"})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	card(r, "guardrails", "audit-guardrail").detail == "the registry does not know this guardrail: a promise the platform never made (guardrails.yaml)"
}

# --- the documents at the gate ----------------------------------------------------

test_spec_missing_fails_the_gate if {
	r := citizen.gate with input as object.remove(fixture.control_input, {"spec"})
	not r.valid
	error_rules(r)["spec/missing"]
	r.verdict == "unreadable"
}

test_registry_missing_fails_the_gate if {
	r := citizen.gate with input as object.remove(fixture.control_input, {"registry"})
	not r.valid
	error_rules(r)["registry/missing"]
	r.verdict == "unreadable"
}

test_spec_version_required if {
	s := fixture.with_field(fixture.spec, {"version": null})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, s, fixture.registry)
	not r.valid
	error_rules(r)["spec/version-required"]
}

test_spec_reviewed_in_future if {
	s := fixture.with_field(fixture.spec, {"reviewedOn": "2026-12-01"})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, s, fixture.registry)
	not r.valid
	error_rules(r)["spec/reviewed-in-future"]
}

test_spec_owner_required if {
	s := fixture.with_field(fixture.spec, {"owner": ""})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, s, fixture.registry)
	not r.valid
	error_rules(r)["spec/owner-required"]
}

test_rails_must_be_array if {
	s := fixture.with_field(fixture.spec, {"actions": "expense.submit"})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, s, fixture.registry)
	not r.valid
	error_rules(r)["rails/must-be-array"]
}

test_coverage_must_be_array if {
	s := fixture.with_field(fixture.spec, {"coverage": "a claim"})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, s, fixture.registry)
	not r.valid
	error_rules(r)["coverage/must-be-array"]
}

test_coverage_row_must_be_string if {
	s := fixture.with_field(fixture.spec, {"coverage": array.concat(fixture.spec.coverage, [7])})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, s, fixture.registry)
	not r.valid
	error_rules(r)["coverage/row-must-be-string"]
}

test_registry_version_required if {
	g := fixture.with_field(fixture.registry, {"version": null})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, fixture.spec, g)
	not r.valid
	error_rules(r)["registry/version-required"]
}

test_datarails_must_be_array if {
	g := fixture.with_field(fixture.registry, {"dataRails": "platform-data-api"})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, fixture.spec, g)
	not r.valid
	error_rules(r)["datarails/must-be-array"]
}

test_platformfloor_row_must_be_object if {
	g := fixture.with_field(fixture.registry, {"platformFloor": array.concat(fixture.registry.platformFloor, ["data-guardrail"])})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, fixture.spec, g)
	not r.valid
	error_rules(r)["platformfloor/row-must-be-object"]
}

test_floor_version_required if {
	g := fixture.with_field(fixture.registry, {"platformFloor": [{"name": "data-guardrail", "floor": null}, {"name": "action-guardrail", "floor": 2}]})
	r := citizen.gate with input as fixture.gate_input(fixture.manifest, fixture.spec, g)
	not r.valid
	error_rules(r)["floor/version-required"]
}

# --- the advisor re-reports the manifest's own findings -----------------------------
#
# The gate is the whole PR-gate answer: the manifest's own stamps
# and shapes ride along with the join, so a manifest the advisor
# cannot read fails honestly — the one red the advisor can show.

test_gate_fails_on_a_manifest_without_its_version if {
	m := fixture.with_field(fixture.manifest, {"version": null})
	r := citizen.gate with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	not r.valid
	error_rules(r)["manifest/version-required"]
	r.verdict == "unreadable"
}

test_gate_fails_on_a_manifest_it_cannot_read_at_all if {
	r := citizen.gate with input as {
		"manifest": "not an object",
		"spec": fixture.spec,
		"registry": fixture.registry,
		"today": fixture.today,
	}
	not r.valid
	error_rules(r)["manifest/missing"]
	r.verdict == "unreadable"
}

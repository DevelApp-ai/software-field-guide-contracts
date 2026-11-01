package citizen.policy_test

import rego.v1

import data.citizen

import data.citizen.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_control_manifest_valid if {
	r := citizen.validate with input as fixture.validate_input(fixture.manifest)
	r.valid == true
	count(r.findings) == 0
}

test_input_must_be_object if {
	r := citizen.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := citizen.validate with input as {"manifest": fixture.manifest, "today": "2026-13-01"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_manifest_missing if {
	r := citizen.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["manifest/missing"]
}

test_version_required if {
	m := fixture.with_field(fixture.manifest, {"version": null})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/version-required"]
}

test_reviewed_on_invalid if {
	m := fixture.with_field(fixture.manifest, {"reviewedOn": "10/01/2026"})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	m := fixture.with_field(fixture.manifest, {"reviewedOn": "2026-12-01"})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/reviewed-in-future"]
}

test_reviewed_stale if {
	m := fixture.with_field(fixture.manifest, {"reviewedOn": "2024-10-01"})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/reviewed-stale"]
}

test_owner_required if {
	m := fixture.with_field(fixture.manifest, {"owner": ""})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/owner-required"]
}

test_app_required if {
	m := fixture.with_field(fixture.manifest, {"app": ""})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/app-required"]
}

test_components_must_be_array if {
	m := fixture.with_field(fixture.manifest, {"components": "form"})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["components/must-be-array"]
}

test_components_row_must_be_object if {
	m := fixture.with_field(fixture.manifest, {"components": array.concat(fixture.manifest.components, ["form"])})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["components/row-must-be-object"]
}

test_component_name_required if {
	m := fixture.with_component_field(fixture.manifest, "claim-form", {"name": ""})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["component/name-required"]
}

test_component_behavior_required if {
	m := fixture.with_component_field(fixture.manifest, "claim-form", {"behavior": ""})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["component/behavior-required"]
}

test_bindings_must_be_array if {
	m := fixture.with_field(fixture.manifest, {"dataBindings": "store"})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["bindings/must-be-array"]
}

test_bindings_row_must_be_object if {
	m := fixture.with_field(fixture.manifest, {"dataBindings": array.concat(fixture.manifest.dataBindings, ["store"])})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["bindings/row-must-be-object"]
}

test_binding_name_required if {
	m := fixture.with_binding_field(fixture.manifest, "claims-store", {"name": ""})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["binding/name-required"]
}

test_binding_mode_unknown if {
	m := fixture.with_binding_field(fixture.manifest, "claims-store", {"mode": "append"})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["binding/mode-unknown"]
}

test_binding_via_required if {
	m := fixture.with_binding_field(fixture.manifest, "claims-store", {"via": ""})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["binding/via-required"]
}

test_actions_must_be_array if {
	m := fixture.with_field(fixture.manifest, {"actions": "expense.submit"})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["actions/must-be-array"]
}

test_actions_row_must_be_string if {
	m := fixture.with_field(fixture.manifest, {"actions": array.concat(fixture.manifest.actions, [7])})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["actions/row-must-be-string"]
}

test_action_name_required if {
	m := fixture.with_field(fixture.manifest, {"actions": ["expense.submit", "   "]})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["action/name-required"]
}

test_action_name_duplicate if {
	m := fixture.with_field(fixture.manifest, {"actions": array.concat(fixture.manifest.actions, ["expense.submit"])})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["action/name-duplicate"]
}

test_guardrails_must_be_array if {
	m := fixture.with_field(fixture.manifest, {"guardrails": "data-guardrail"})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["guardrails/must-be-array"]
}

test_guardrails_row_must_be_object if {
	m := fixture.with_field(fixture.manifest, {"guardrails": array.concat(fixture.manifest.guardrails, ["data-guardrail"])})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["guardrails/row-must-be-object"]
}

test_guardrail_name_required if {
	m := fixture.with_guardrail_field(fixture.manifest, "data-guardrail", {"name": ""})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["guardrail/name-required"]
}

test_guardrail_version_required if {
	m := fixture.with_guardrail_field(fixture.manifest, "data-guardrail", {"version": null})
	r := citizen.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["guardrail/version-required"]
}

# --- lib parity: the date helpers are a verbatim copy of the estate lib ------

test_epoch_is_day_zero if {
	citizen.lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	citizen.lib.date_to_days("2026-10-20") - citizen.lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not citizen.lib.is_valid_date("2026-02-30")
}

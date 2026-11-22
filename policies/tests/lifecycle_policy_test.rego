package lifecycle.policy_test

import rego.v1

import data.lifecycle

import data.lifecycle.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the control: the lifecycle record validates alone -------------------------

test_control_record_validates if {
	r := lifecycle.validate with input as fixture.validate_input(fixture.record_doc)
	r.valid == true
	count(r.findings) == 0
}

# --- lib parity: the copy never drifts from the estate lib -----------------------

test_lib_parity_is_valid_date if {
	data.lifecycle.lib.is_valid_date("2026-10-20") == data.estate.lib.is_valid_date("2026-10-20")
	data.lifecycle.lib.is_valid_date("2024-02-29") == data.estate.lib.is_valid_date("2024-02-29")
	not data.lifecycle.lib.is_valid_date("2026-02-30")
	not data.estate.lib.is_valid_date("2026-02-30")
	not data.lifecycle.lib.is_valid_date("not a date")
	not data.estate.lib.is_valid_date("not a date")
}

test_lib_parity_date_to_days if {
	data.lifecycle.lib.date_to_days("2026-10-20") == data.estate.lib.date_to_days("2026-10-20")
	data.lifecycle.lib.date_to_days("1970-01-01") == data.estate.lib.date_to_days("1970-01-01")
	data.lifecycle.lib.date_to_days("2024-02-29") == data.estate.lib.date_to_days("2024-02-29")
	data.lifecycle.lib.date_to_days("2000-03-01") == data.estate.lib.date_to_days("2000-03-01")
}

test_lib_parity_days_in_month if {
	data.lifecycle.lib.days_in_month(2024, 2) == data.estate.lib.days_in_month(2024, 2)
	data.lifecycle.lib.days_in_month(2026, 2) == data.estate.lib.days_in_month(2026, 2)
	data.lifecycle.lib.days_in_month(2026, 4) == data.estate.lib.days_in_month(2026, 4)
	data.lifecycle.lib.days_in_month(2026, 12) == data.estate.lib.days_in_month(2026, 12)
}

test_lib_parity_is_nonempty_string if {
	data.lifecycle.lib.is_nonempty_string("payments-checkout") == data.estate.lib.is_nonempty_string("payments-checkout")
	not data.lifecycle.lib.is_nonempty_string(" ")
	not data.estate.lib.is_nonempty_string(" ")
	not data.lifecycle.lib.is_nonempty_string("")
	not data.estate.lib.is_nonempty_string("")
	not data.lifecycle.lib.is_nonempty_string(42)
	not data.estate.lib.is_nonempty_string(42)
}

# --- the input and the clock ------------------------------------------------------

test_input_invalid if {
	r := lifecycle.validate with input as "not an object"
	not r.valid
	error_rules(r)["input/invalid"]
}

test_today_invalid if {
	i := object.union(fixture.validate_input(fixture.record_doc), {"today": "2026-13-01"})
	r := lifecycle.validate with input as i
	not r.valid
	error_rules(r)["input/today-invalid"]
}

# --- the lifecycle record document is missing -------------------------------------

test_record_missing if {
	r := lifecycle.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["lifecycle/missing"]
}

# --- the record stamps --------------------------------------------------------------

test_lifecycle_version_required if {
	m := fixture.with_field(fixture.record_doc, {"version": null})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["lifecycle/version-required"]
}

test_lifecycle_reviewed_on_invalid if {
	m := fixture.with_field(fixture.record_doc, {"reviewedOn": "2026-02-30"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["lifecycle/reviewed-on-invalid"]
}

test_lifecycle_reviewed_in_future if {
	m := fixture.with_field(fixture.record_doc, {"reviewedOn": "2026-12-01"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["lifecycle/reviewed-in-future"]
}

test_lifecycle_reviewed_stale if {
	m := fixture.with_field(fixture.record_doc, {"reviewedOn": "2024-10-01"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["lifecycle/reviewed-stale"]
}

test_lifecycle_owner_required if {
	m := fixture.with_field(fixture.record_doc, {"owner": " "})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["lifecycle/owner-required"]
}

test_lifecycle_component_required if {
	m := fixture.with_field(fixture.record_doc, {"component": ""})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["lifecycle/component-required"]
}

# --- the transitions array -----------------------------------------------------------

test_transitions_must_be_array if {
	m := fixture.with_field(fixture.record_doc, {"transitions": "a bake, a patch, and an upgrade"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transitions/must-be-array"]
}

test_transitions_rows_required if {
	m := fixture.with_transitions(fixture.record_doc, [])
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transitions/rows-required"]
}

test_transitions_row_must_be_object if {
	m := fixture.with_transitions(fixture.record_doc, ["a bake happened"])
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transitions/row-must-be-object"]
}

# --- the transition's type and stamp ---------------------------------------------------

test_transition_type_required if {
	m := fixture.with_transition_field(fixture.record_doc, "bake", {"type": null})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/type-required"]
}

test_transition_type_unknown if {
	m := fixture.with_transition_field(fixture.record_doc, "bake", {"type": "deploy"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/type-unknown"]
}

test_transition_recorded_on_required if {
	m := fixture.with_transition_field(fixture.record_doc, "bake", {"recordedOn": null})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/recorded-on-required"]
}

test_transition_recorded_on_invalid if {
	m := fixture.with_transition_field(fixture.record_doc, "bake", {"recordedOn": "2026-02-30"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/recorded-on-invalid"]
}

test_transition_recorded_in_future if {
	m := fixture.with_transition_field(fixture.record_doc, "bake", {"recordedOn": "2026-11-01"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/recorded-in-future"]
}

test_transition_recorded_after_review if {
	m := fixture.with_transition_field(fixture.record_doc, "patch", {"recordedOn": "2026-10-19"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/recorded-after-review"]
}

test_transition_duplicate if {
	m := fixture.with_transitions(fixture.record_doc, array.concat(fixture.record_doc.transitions, [fixture.record_doc.transitions[0]]))
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/duplicate"]
}

# --- the bake evidence -------------------------------------------------------------------

test_bake_digest_required if {
	m := fixture.with_transition_field(fixture.record_doc, "bake", {"imageDigest": null})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/bake-digest-required"]
}

test_bake_digest_malformed if {
	m := fixture.with_transition_field(fixture.record_doc, "bake", {"imageDigest": "5766fab"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/bake-digest-malformed"]
}

# --- the patch evidence -----------------------------------------------------------------

test_patch_provenance_required if {
	m := fixture.with_transition_field(fixture.record_doc, "patch", {"provenance": "a patch was applied"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/patch-provenance-required"]
}

test_patch_provenance_source_required if {
	m := fixture.with_transition_field(fixture.record_doc, "patch", {"provenance": {"source": " ", "commit": "9f31c0e"}})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/patch-provenance-source-required"]
}

test_patch_provenance_commit_required if {
	m := fixture.with_transition_field(fixture.record_doc, "patch", {"provenance": {"source": "payments/checkout.git", "commit": ""}})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/patch-provenance-commit-required"]
}

# --- the upgrade evidence ----------------------------------------------------------------

test_upgrade_rollback_required if {
	m := fixture.with_transition_field(fixture.record_doc, "upgrade", {"rollback": "we rehearsed the way back"})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/upgrade-rollback-required"]
}

test_upgrade_rehearsed_on_required if {
	m := fixture.with_transition_field(fixture.record_doc, "upgrade", {"rollback": {}})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/upgrade-rehearsed-on-required"]
}

test_upgrade_rehearsed_on_invalid if {
	m := fixture.with_transition_field(fixture.record_doc, "upgrade", {"rollback": {"rehearsedOn": "2026-13-01"}})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/upgrade-rehearsed-on-invalid"]
}

test_upgrade_rehearsed_in_future if {
	m := fixture.with_transition_field(fixture.record_doc, "upgrade", {"rollback": {"rehearsedOn": "2026-11-05"}})
	r := lifecycle.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["transition/upgrade-rehearsed-in-future"]
}

package compliance.policy_test

import rego.v1

import data.compliance

import data.compliance.fixture

import data.compliance.lib

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the control: the seeded controls manifest validates alone -------------------

test_control_manifest_validates if {
	r := compliance.validate with input as fixture.validate_input(fixture.controls_manifest)
	r.valid == true
	count(r.findings) == 0
}

test_validate_answers_in_the_stable_shape if {
	r := compliance.validate with input as fixture.validate_input(fixture.controls_manifest)
	object.keys(r) == {"findings", "valid"}
}

test_input_must_be_object if {
	r := compliance.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := compliance.validate with input as {"controls": fixture.controls_manifest, "today": "2026-13-01"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_controls_missing if {
	r := compliance.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["controls/missing"]
}

# --- the manifest's own stamps -------------------------------------------------

test_version_required if {
	m := fixture.with_field(fixture.controls_manifest, {"version": null})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["controls/version-required"]
}

test_reviewed_on_invalid if {
	m := fixture.with_field(fixture.controls_manifest, {"reviewedOn": "10/01/2026"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["controls/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	m := fixture.with_field(fixture.controls_manifest, {"reviewedOn": "2026-12-01"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["controls/reviewed-in-future"]
}

test_reviewed_stale if {
	m := fixture.with_field(fixture.controls_manifest, {"reviewedOn": "2024-10-01"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["controls/reviewed-stale"]
}

test_owner_required if {
	m := fixture.with_field(fixture.controls_manifest, {"owner": ""})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["controls/owner-required"]
}

# --- the control rows -----------------------------------------------------------

test_controls_must_be_array if {
	m := fixture.with_field(fixture.controls_manifest, {"controls": "CTRL-01"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["controls/must-be-array"]
}

test_controls_required if {
	m := fixture.with_field(fixture.controls_manifest, {"controls": []})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	some f in r.findings
	f.rule == "controls/required"
	contains(f.message, "an empty manifest claims the estate controls nothing")
}

test_row_must_be_object if {
	m := fixture.with_field(fixture.controls_manifest, {"controls": array.concat(["CTRL-01"], fixture.controls_manifest.controls)})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/row-must-be-object"]
}

test_control_id_required if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-01", {"id": ""})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/id-required"]
}

test_control_id_duplicate if {
	m := object.union(fixture.controls_manifest, {"controls": array.concat(fixture.controls_manifest.controls, [fixture.controls_manifest.controls[0]])})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	count([f | some f in r.findings; f.rule == "control/id-duplicate"]) == 1
}

test_control_title_required if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-01", {"title": " "})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/title-required"]
}

test_control_owner_required if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-02", {"owner": ""})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/owner-required"]
}

# The control's reason to exist: its requirement mappings.
test_control_requirements_must_be_array if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-01", {"requirements": "PCI-DSS-2.2.7"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/requirements-must-be-array"]
}

test_control_requirements_required if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-01", {"requirements": []})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	some f in r.findings
	f.rule == "control/requirements-required"
	contains(f.message, "an unmapped control is busywork with no compliance meaning")
}

test_control_requirement_must_be_string if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-01", {"requirements": [1]})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/requirement-must-be-string"]
}

# The control's evidence citation, the reason it is a control and not
# an assertion.
test_control_evidence_required if {
	m := object.remove(fixture.with_control_field(fixture.controls_manifest, "CTRL-02", {"evidenceSource": ""}), {"evidenceSource"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	some f in r.findings
	f.rule == "control/evidence-required"
	contains(f.message, "a control without evidence is an assertion, not a control")
	f.path == "$.controls.controls[1].evidenceSource"
}

# --- the review clock's own shape --------------------------------------------------

test_control_reviewed_on_invalid if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-01", {"reviewedOn": "2026-9-15"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/reviewed-on-invalid"]
}

test_control_reviewed_in_future if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-01", {"reviewedOn": "2026-12-01"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/reviewed-in-future"]
}

test_control_interval_required if {
	m := object.remove(fixture.with_control_field(fixture.controls_manifest, "CTRL-03", {"intervalDays": null}), {"intervalDays"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/interval-required"]
}

test_control_interval_invalid if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-03", {"intervalDays": 0})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["control/interval-invalid"]
}

# --- the named evidence sources -------------------------------------------------------

test_sources_must_be_array if {
	m := fixture.with_field(fixture.controls_manifest, {"evidenceSources": "edge-firewall-review"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["sources/must-be-array"]
}

test_source_row_must_be_object if {
	m := fixture.with_field(fixture.controls_manifest, {"evidenceSources": array.concat(["edge-firewall-review"], fixture.controls_manifest.evidenceSources)})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["source/row-must-be-object"]
}

test_source_id_required if {
	m := fixture.with_source_field(fixture.controls_manifest, "edge-firewall-review", {"id": ""})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["source/id-required"]
}

test_source_kind_required if {
	m := fixture.with_source_field(fixture.controls_manifest, "edge-access-logs", {"kind": ""})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["source/kind-required"]
}

test_source_status_unknown if {
	m := fixture.with_source_field(fixture.controls_manifest, "encryption-config-scan", {"status": "mostly"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	some f in r.findings
	f.rule == "source/status-unknown"
	contains(f.message, "neither live nor retired")
}

test_source_id_duplicate if {
	s := fixture.controls_manifest.evidenceSources[0]
	m := object.union(fixture.controls_manifest, {"evidenceSources": array.concat(fixture.controls_manifest.evidenceSources, [object.union(s, {"kind": "report"})])})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	count([f | some f in r.findings; f.rule == "source/id-duplicate"]) == 1
}

# --- the citation join inside the manifest ----------------------------------------------

test_evidence_source_unknown if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-02", {"evidenceSource": "old-encryption-scan"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	some f in r.findings
	f.rule == "control/evidence-source-unknown"
	contains(f.message, "CTRL-02")
	contains(f.message, "old-encryption-scan")
	contains(f.message, "a citation that resolves nowhere is evidence nobody collects")
}

test_declared_sources_cited_freely if {
	r := compliance.validate with input as fixture.validate_input(fixture.controls_manifest)
	not error_rules(r)["control/evidence-source-unknown"]
}

test_a_manifest_with_no_source_rows_is_forbidden_by_the_citation_join if {
	m := object.remove(fixture.controls_manifest, {"evidenceSources"})
	r := compliance.validate with input as fixture.validate_input(m)
	not r.valid
	count([f | some f in r.findings; f.rule == "control/evidence-source-unknown"]) == 4
}

# --- lib parity: the date helpers are a verbatim copy of the estate lib ------

test_epoch_is_day_zero if {
	lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	lib.date_to_days("2026-10-20") - lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not lib.is_valid_date("2026-02-30")
}

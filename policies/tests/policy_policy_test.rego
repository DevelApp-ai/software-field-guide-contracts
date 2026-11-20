package policy.policy_test

import rego.v1

import data.policy

import data.policy.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the control: three admitted rows, all readable ----------------------------

test_control_catalog_validates if {
	r := policy.validate with input as fixture.validate_input(fixture.catalog)
	r.valid == true
	count(r.findings) == 0
}

# --- findings: the input and the clock --------------------------------------------

test_input_must_be_an_object if {
	r := policy.validate with input as "not an object"
	not r.valid
	error_rules(r)["input/invalid"]
}

test_today_must_be_a_real_date if {
	r := policy.validate with input as object.union(fixture.validate_input(fixture.catalog), {"today": "2026-13-01"})
	not r.valid
	error_rules(r)["input/today-invalid"]
}

# --- findings: the catalog document ----------------------------------------------

test_catalog_missing if {
	i := object.remove(fixture.validate_input(fixture.catalog), {"catalog"})
	r := policy.validate with input as i
	not r.valid
	error_rules(r)["catalog/missing"]
}

test_catalog_version_required if {
	c := fixture.with_field(fixture.catalog, {"version": null})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["catalog/version-required"]
}

test_catalog_version_must_be_positive if {
	c := fixture.with_field(fixture.catalog, {"version": 0})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["catalog/version-required"]
}

test_catalog_reviewed_on_invalid if {
	c := fixture.with_field(fixture.catalog, {"reviewedOn": "October the eighteenth"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["catalog/reviewed-on-invalid"]
}

test_catalog_reviewed_in_future if {
	c := fixture.with_field(fixture.catalog, {"reviewedOn": "2026-12-01"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["catalog/reviewed-in-future"]
}

test_catalog_reviewed_stale if {
	c := fixture.with_field(fixture.catalog, {"reviewedOn": "2024-10-01"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["catalog/reviewed-stale"]
}

test_catalog_owner_required if {
	c := fixture.with_field(fixture.catalog, {"owner": ""})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["catalog/owner-required"]
}

# --- findings: the policies array ----------------------------------------------------

test_policies_must_be_array if {
	c := fixture.with_field(fixture.catalog, {"policies": "pci-scan"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policies/must-be-array"]
}

test_policies_rows_required if {
	c := fixture.with_field(fixture.catalog, {"policies": null})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policies/rows-required"]
}

test_policy_row_must_be_object if {
	c := fixture.with_field(fixture.catalog, {"policies": ["pci-scan"]})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policies/row-must-be-object"]
}

# --- findings: one policy component row ---------------------------------------------

test_policy_name_required if {
	c := fixture.with_catalog_row_field(fixture.catalog, "tier-egress", {"policy": ""})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/name-required"]
}

test_policy_name_duplicate if {
	dup := [x | some x in fixture.catalog.policies; object.get(x, "policy", null) == "tier-egress"][0]
	c := fixture.with_field(fixture.catalog, {"policies": array.concat(fixture.catalog.policies, [object.union(dup, {"version": "9.9.9"})])})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/name-duplicate"]
}

test_policy_version_required if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"version": null})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/version-required"]
}

test_policy_digest_required if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"digest": null})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/digest-required"]
}

test_policy_digest_malformed if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"digest": "deadbeef"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/digest-malformed"]
}

test_policy_signature_required if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"signature": null})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/signature-required"]
}

test_policy_signature_key_required if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"signature": {"signedDigest": "b09dcc492429e5e410c918a3d27911639f00759d86cd5d87612a23e15e11c324"}})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/signature-key-required"]
}

test_policy_signature_digest_required if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"signature": {"keyId": "key-2026-q4"}})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/signature-digest-required"]
}

# The honesty rule: the recorded evidence must be internally
# consistent — the validator does not check cryptographic validity.
test_policy_signature_digest_mismatch if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"signature": {"keyId": "key-2026-q4", "signedDigest": "54e34a23f2c451616380d3c5432537f6e7d3df96a88e3361cc2b9674f5c289fc"}})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/signature-digest-mismatch"]
}

# --- findings: the posture ladder ------------------------------------------------

test_policy_posture_required if {
	c := fixture.with_catalog_row_field(fixture.catalog, "tier-egress", {"posture": null})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/posture-required"]
}

test_policy_posture_unknown if {
	c := fixture.with_catalog_row_field(fixture.catalog, "tier-egress", {"posture": "mostly-enforced"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/posture-unknown"]
}

# Every rung of the ladder is legal — audit honestly differs from
# enforce, and that difference is the point of recording it.
test_every_posture_on_the_ladder_is_known if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"posture": "warn"})
	r := policy.validate with input as fixture.validate_input(c)
	r.valid == true
}

# --- findings: the exact path rules -----------------------------------------------

test_policy_path_required if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"path": null})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/path-required"]
}

test_policy_path_glob_star if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"path": "/policies/pci-*.rego"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/path-glob"]
}

test_policy_path_glob_bracket if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"path": "/policies/pci-[sv]can.rego"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/path-glob"]
}

test_policy_path_glob_brace if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"path": "/policies/{pci,tier}/scan.rego"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/path-glob"]
}

test_policy_path_glob_question_mark if {
	c := fixture.with_catalog_row_field(fixture.catalog, "pci-scan", {"path": "/policies/pci-scan?.rego"})
	r := policy.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["policy/path-glob"]
}

# --- lib parity: the date helpers are a verbatim copy of the estate lib ------

test_epoch_is_day_zero if {
	policy.lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	policy.lib.date_to_days("2026-10-20") - policy.lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not policy.lib.is_valid_date("2026-02-30")
}

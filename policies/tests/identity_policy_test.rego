package identity.policy_test

import rego.v1

import data.identity

import data.identity.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the control: the seeded estate validates --------------------------------

test_control_manifest_valid if {
	r := identity.validate with input as fixture.validate_input(fixture.manifest)
	r.valid == true
	count(r.findings) == 0
}

# --- the input and the injected clock ------------------------------------------

test_input_must_be_object if {
	r := identity.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := identity.validate with input as {"manifest": fixture.manifest, "today": "2026-13-01"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

# --- the manifest and its house stamps ------------------------------------------

test_manifest_missing if {
	r := identity.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["manifest/missing"]
}
test_version_required if {
	m := fixture.with_field(fixture.manifest, {"version": null})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/version-required"]
}
test_reviewed_on_invalid if {
	m := fixture.with_field(fixture.manifest, {"reviewedOn": "18/10/2026"})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/reviewed-on-invalid"]
}
test_reviewed_in_future if {
	m := fixture.with_field(fixture.manifest, {"reviewedOn": "2026-12-01"})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/reviewed-in-future"]
}
test_reviewed_stale if {
	m := fixture.with_field(fixture.manifest, {"reviewedOn": "2024-10-01"})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/reviewed-stale"]
}
test_owner_required if {
	m := fixture.with_field(fixture.manifest, {"owner": null})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["manifest/owner-required"]
}

# --- the identities the manifest declares -----------------------------------------

test_identities_must_be_array if {
	m := fixture.with_field(fixture.manifest, {"identities": 7})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["identities/must-be-array"]
}
test_identity_required if {
	m := fixture.with_field(fixture.manifest, {"identities": []})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["identities/required"]
}
test_identity_row_must_be_object if {
	m := fixture.with_field(fixture.manifest, {"identities": ["checkout-web"]})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["identities/row-must-be-object"]
}
test_identity_name_required if {
	m := fixture.with_identity_field(fixture.manifest, "billing-exporter", {"name": null})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["identity/name-required"]
}

# The duplicate identity: the issue's named broken variant. One
# app, two identity rows — whichever row the finding cites, the set
# reports it once.
test_identity_name_duplicate if {
	m := object.union(fixture.manifest, {"identities": array.concat(fixture.manifest.identities, [{
		"name": "checkout-web",
		"references": [],
	}])})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	count([f | some f in r.findings; f.rule == "identity/name-duplicate"]) == 1
	error_rules(r)["identity/name-duplicate"]
}

# --- the references each identity declares ------------------------------------

test_references_must_be_array if {
	m := fixture.with_identity_field(fixture.manifest, "checkout-web", {"references": "all of them"})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["references/must-be-array"]
}
test_references_row_must_be_object if {
	m := fixture.with_identity_field(fixture.manifest, "checkout-web", {"references": ["payments-api-key"]})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["references/row-must-be-object"]
}
test_reference_secret_required if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"secret": null})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["reference/secret-required"]
}
test_reference_scope_required if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"scope": null})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["reference/scope-required"]
}

# --- scope minimality: the manifest's own words ----------------------------------

# The wildcard scope: the issue's named broken variant. A scope that
# means everything means the platform granted nothing it can name.
test_reference_scope_wildcard if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"scope": "*"})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	count([f | some f in r.findings; f.rule == "reference/scope-wildcard"]) == 1
	error_rules(r)["reference/scope-wildcard"]
}
test_reference_scope_glob if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"scope": "payments:*"})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["reference/scope-glob"]
}

# --- since when the reference existed -------------------------------------------

test_reference_since_invalid if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"since": "yesterday"})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["reference/since-invalid"]
}
test_reference_since_in_future if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"since": "2026-12-01"})
	r := identity.validate with input as fixture.validate_input(m)
	not r.valid
	error_rules(r)["reference/since-in-future"]
}

# --- lib parity: the date helpers are a verbatim copy of the estate lib ------

test_epoch_is_day_zero if {
	identity.lib.date_to_days("1970-01-01") == 0
}
test_consecutive_days if {
	identity.lib.date_to_days("2026-10-20") - identity.lib.date_to_days("2026-10-19") == 1
}
test_impossible_date_rejected if {
	not identity.lib.is_valid_date("2026-02-30")
}
test_leap_february_accepted if {
	identity.lib.is_valid_date("2028-02-29")
}

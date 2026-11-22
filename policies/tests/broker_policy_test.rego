# The IAM-broker scope validator, rule by rule: every finding body
# has a test that bites it, and the control broker document has one
# that validates clean. The fixture is the #104 worked example; the
# overrides change one field at a time, so every test answers for
# exactly the rule it names. The lib parity tests pin the date
# arithmetic in-repo: leap days, invalid calendar dates, and the
# epoch anchor.
package broker.policy_test

import rego.v1

import data.broker

import data.broker.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the control -------------------------------------------------------------

test_control_broker_document_validates if {
	r := broker.validate with input as fixture.validate_input(fixture.broker_doc)
	r.valid == true
	count(r.findings) == 0
}

# --- the input and the clock ---------------------------------------------------

test_input_must_be_an_object if {
	r := broker.validate with input as "nope"
	error_rules(r)["input/invalid"]
}

test_today_must_be_a_real_date if {
	r := broker.validate with input as object.union(fixture.validate_input(fixture.broker_doc), {"today": "2026-13-01"})
	error_rules(r)["input/today-invalid"]
}

# --- the broker grant document ---------------------------------------------------

test_broker_document_is_required if {
	r := broker.validate with input as {"today": fixture.today, "brokerFile": fixture.broker_file}
	error_rules(r)["broker/missing"]
	count([f | some f in r.findings; f.rule == "input/invalid"]) == 0
}

test_version_stamp_is_required if {
	b := fixture.with_field(fixture.broker_doc, {"version": null})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["broker/version-required"]
}

test_reviewed_on_must_be_a_real_date if {
	b := fixture.with_field(fixture.broker_doc, {"reviewedOn": "18.10.2026"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["broker/reviewed-on-invalid"]
}

test_reviewed_on_in_the_future if {
	b := fixture.with_field(fixture.broker_doc, {"reviewedOn": "2026-11-01"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["broker/reviewed-in-future"]
}

test_reviewed_on_stale if {
	b := fixture.with_field(fixture.broker_doc, {"reviewedOn": "2024-10-01"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["broker/reviewed-stale"]
}

test_owner_is_required if {
	b := fixture.with_field(fixture.broker_doc, {"owner": ""})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["broker/owner-required"]
}

# --- the declared consumer identities --------------------------------------------

test_principals_must_be_an_array if {
	b := fixture.with_field(fixture.broker_doc, {"principals": "storefront-build"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["principals/must-be-array"]
}

test_principal_names_are_required if {
	b := fixture.with_field(fixture.broker_doc, {"principals": ["storefront-build", ""]})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["principals/name-required"]
}

test_declared_identity_twice if {
	b := fixture.with_field(fixture.broker_doc, {"principals": ["storefront-build", "storefront-build"]})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["principal/name-duplicate"]
}

# --- the grant rows ----------------------------------------------------------------

test_grants_must_be_an_array if {
	b := fixture.with_field(fixture.broker_doc, {"grants": "nope"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grants/must-be-array"]
}

test_at_least_one_grant if {
	b := fixture.with_field(fixture.broker_doc, {"grants": []})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grants/rows-required"]
}

test_grant_row_must_be_an_object if {
	b := fixture.with_field(fixture.broker_doc, {"grants": ["nope"]})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grants/row-must-be-object"]
}

# --- each grant's named identity ----------------------------------------------------

test_grant_principal_required if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"principal": null})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/principal-required"]
}

test_grant_principal_must_be_declared if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"principal": "quarantine-scanner"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/principal-undeclared"]
}

test_grant_component_required if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"component": ""})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/component-required"]
}

test_the_same_grant_twice if {
	b := fixture.with_grant_field(fixture.broker_doc, 1, {"principal": "storefront-build", "component": "payments-checkout"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/duplicate"]
}

# --- each grant's pinned digest ------------------------------------------------------

test_grant_digest_required if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"digest": null})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/digest-required"]
}

test_grant_digest_malformed if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"digest": "5766fab"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/digest-malformed"]
}

# --- each grant's allowed action set --------------------------------------------------

test_grant_actions_must_be_an_array if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": "pull"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/actions-must-be-array"]
}

test_grant_actions_required if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": []})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/actions-required"]
}

test_grant_action_name_required if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": ["", "pull"]})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/action-name-required"]
}

test_wildcard_action_refused if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": ["*"]})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/action-wildcard"]

	# Exactly the wildcard, not a glob: a lone "*" is a different
	# finding than a metacharacter.
	count([f | some f in r.findings; f.rule == "grant/action-glob"]) == 0
}

test_glob_action_refused if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": ["pull*"]})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/action-glob"]
	count([f | some f in r.findings; f.rule == "grant/action-wildcard"]) == 0
}

test_bracket_action_refused if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": ["pull[prod]"]})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/action-glob"]
}

test_duplicate_action if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": ["pull", "pull"]})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/action-duplicate"]
}

# --- each grant's expiry ---------------------------------------------------------------

test_grant_expiry_required if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"expires": null})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/expires-required"]
}

test_grant_expiry_must_be_a_real_date if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"expires": "2026-02-30"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/expires-invalid"]
}

test_expired_grant_still_on_the_books if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"expires": "2026-10-01"})
	r := broker.validate with input as fixture.validate_input(b)
	error_rules(r)["grant/expires-in-past"]
}

# Expiry on exactly today is still live: the grant dies after today,
# not on it.
test_grant_expiring_today_is_not_past if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"expires": "2026-10-20"})
	r := broker.validate with input as fixture.validate_input(b)
	count([f | some f in r.findings; f.rule == "grant/expires-in-past"]) == 0
}

# --- lib parity: the date arithmetic, pinned in-repo -------------------------------------

test_the_epoch_anchors_the_clock if {
	broker.lib.date_to_days("1970-01-01") == 0
}

test_days_advance_one_day_at_a_time if {
	broker.lib.date_to_days("2026-10-21") == broker.lib.date_to_days("2026-10-20") + 1
}

test_leap_days_are_real_when_the_calendar_says_so if {
	broker.lib.is_valid_date("2028-02-29")
	not broker.lib.is_valid_date("2027-02-29")
	not broker.lib.is_valid_date("2026-02-30")
}

test_year_boundaries_cross_honestly if {
	days_2026 := broker.lib.date_to_days("2026-12-31")
	days_2027 := broker.lib.date_to_days("2027-01-01")
	days_2027 == days_2026 + 1
}

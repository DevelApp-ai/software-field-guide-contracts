package erasure.policy_test

import rego.v1

import data.erasure

import data.erasure.fixture

import data.erasure.lib

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_valid_registry_passes if {
	r := erasure.validate with input as fixture.validate_input(fixture.keys)
	r.valid == true
	count(r.findings) == 0
}

test_input_must_be_object if {
	r := erasure.validate with input as "nope"
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := erasure.validate with input as {"keys": fixture.keys, "today": "yesterday"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_missing_keys if {
	r := erasure.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["keys/missing"]
}

# --- stamps -------------------------------------------------------------------

test_version_required if {
	k := object.remove(fixture.keys, ["version"])
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["keys/version-required"]
}

test_reviewed_on_invalid if {
	k := object.union(fixture.keys, {"reviewedOn": "2026-02-30"})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["keys/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	k := object.union(fixture.keys, {"reviewedOn": "2026-10-21"})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["keys/reviewed-in-future"]
}

test_reviewed_stale if {
	k := object.union(fixture.keys, {"reviewedOn": "2025-10-19"})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["keys/reviewed-stale"]
}

# --- the key rows ---------------------------------------------------------------

test_keys_must_be_array if {
	k := object.remove(fixture.keys, ["keys"])
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["keys/must-be-array"]
}

test_keys_required if {
	k := object.union(fixture.keys, {"keys": []})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["keys/required"]
}

test_row_must_be_object if {
	k := object.union(fixture.keys, {"keys": ["a string"]})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	some f in r.findings
	f.rule == "keys/row-must-be-object"
	f.path == "$.keys.keys[0]"
}

test_dek_required if {
	k := fixture.with_key_field(fixture.keys, "tenant-initech-dek-001", {"dek": ""})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["key/dek-required"]
}

test_tenant_required if {
	k := fixture.with_key_field(fixture.keys, "tenant-initech-dek-001", {"tenant": ""})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["key/tenant-required"]
}

test_state_unknown if {
	k := fixture.with_key_field(fixture.keys, "tenant-initech-dek-001", {"state": "misplaced"})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	some f in r.findings
	f.rule == "key/state-unknown"
	contains(f.message, "neither active nor destroyed")
}

test_destroyed_at_invalid if {
	k := fixture.with_key_field(fixture.keys, "tenant-acme-dek-004", {"destroyedAt": "2026-02-30"})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["key/destroyed-at-invalid"]
}

test_destroyed_in_future if {
	k := fixture.with_key_field(fixture.keys, "tenant-acme-dek-004", {"destroyedAt": "2026-10-21"})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["key/destroyed-in-future"]
}

# The issue's seeded registry variant: a destruction without its
# evidence record is a deletion asserted, not evidenced.
test_destroyed_by_required if {
	k := fixture.without_key_field(fixture.keys, "tenant-acme-dek-004", "destroyedBy")
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	some f in r.findings
	f.rule == "key/destroyed-by-required"
	f.path == "$.keys.keys[0].destroyedBy"
	contains(f.message, "destruction needs its evidence record")
}

test_active_key_with_destruction_evidence if {
	k := fixture.with_key_field(fixture.keys, "tenant-initech-dek-001", {"destroyedAt": "2026-10-10"})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	some f in r.findings
	f.rule == "key/active-with-evidence"
	contains(f.message, "the state and the record disagree")
}

test_dek_duplicate if {
	k := object.union(fixture.keys, {"keys": array.concat(fixture.keys.keys, [object.union(fixture.keys.keys[0], {"tenant": "tenant-globex"})])})
	r := erasure.validate with input as fixture.validate_input(k)
	not r.valid
	error_rules(r)["key/dek-duplicate"]
}

test_live_tenancy_passes if {
	# an active key with no destruction evidence is the honest state of
	# a live tenancy — the registry judges evidence, not existence
	r := erasure.validate with input as fixture.validate_input(fixture.keys)
	r.valid == true
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

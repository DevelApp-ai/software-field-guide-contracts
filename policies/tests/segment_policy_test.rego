package segment.policy_test

import rego.v1

import data.segment

import data.segment.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_control_contract_valid if {
	r := segment.validate with input as fixture.validate_input(fixture.contract)
	r.valid == true
	count(r.findings) == 0
}

test_input_must_be_object if {
	r := segment.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := segment.validate with input as {"contract": fixture.contract, "today": "2026-13-01"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_contract_missing if {
	r := segment.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["contract/missing"]
}

test_version_required if {
	c := fixture.with_field(fixture.contract, {"version": null})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/version-required"]
}

test_reviewed_on_invalid if {
	c := fixture.with_field(fixture.contract, {"reviewedOn": "10/01/2026"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	c := fixture.with_field(fixture.contract, {"reviewedOn": "2026-12-01"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/reviewed-in-future"]
}

test_reviewed_stale if {
	c := fixture.with_field(fixture.contract, {"reviewedOn": "2024-10-01"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/reviewed-stale"]
}

test_owner_required if {
	c := fixture.with_field(fixture.contract, {"owner": ""})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/owner-required"]
}

test_segments_must_be_array if {
	c := fixture.with_field(fixture.contract, {"segments": "web"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["segments/must-be-array"]
}

test_segments_required if {
	c := fixture.with_field(fixture.contract, {"segments": []})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["segments/required"]
}

test_segment_must_be_string if {
	c := fixture.with_field(fixture.contract, {"segments": ["web", 7]})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["segment/must-be-string"]
}

test_segment_name_required if {
	c := fixture.with_field(fixture.contract, {"segments": ["web", "   "]})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["segment/name-required"]
}

test_segment_duplicate if {
	c := fixture.with_field(fixture.contract, {"segments": ["web", "api", "web"]})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["segment/name-duplicate"]
}

test_rules_must_be_array if {
	c := fixture.with_field(fixture.contract, {"rules": "R1"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rules/must-be-array"]
}

test_rules_required if {
	c := fixture.with_field(fixture.contract, {"rules": []})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rules/required"]
}

test_rules_row_must_be_object if {
	c := fixture.with_field(fixture.contract, {"rules": array.concat(fixture.contract.rules, ["R5"])})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rules/row-must-be-object"]
}

test_rule_id_required if {
	c := fixture.with_rule_field(fixture.contract, "R1", {"id": ""})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/id-required"]
}

test_rule_from_required if {
	c := fixture.with_rule_field(fixture.contract, "R1", {"from": ""})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/from-required"]
}

test_rule_to_required if {
	c := fixture.with_rule_field(fixture.contract, "R1", {"to": ""})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/to-required"]
}

test_rule_leaves_from_undeclared_segment if {
	c := fixture.with_rule_field(fixture.contract, "R1", {"from": "edge"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/segment-undeclared"]
}

test_rule_enters_undeclared_segment if {
	c := fixture.with_rule_field(fixture.contract, "R1", {"to": "edge"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/segment-undeclared"]
}

test_rule_type_outside_modeled_subset if {
	c := fixture.with_rule_field(fixture.contract, "R1", {"type": "sctp"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/type-unknown"]
}

test_rule_port_invalid if {
	c := fixture.with_rule_field(fixture.contract, "R1", {"port": 70000})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/port-invalid"]
}

test_rule_direction_unknown if {
	c := fixture.with_rule_field(fixture.contract, "R1", {"direction": "north"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/direction-unknown"]
}

test_rule_mode_unknown if {
	c := fixture.with_rule_field(fixture.contract, "R1", {"mode": "maybe"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/mode-unknown"]
}

test_rule_id_duplicate if {
	c := fixture.with_field(fixture.contract, {"rules": array.concat(fixture.contract.rules, [fixture.contract.rules[0]])})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["rule/id-duplicate"]
}

test_exception_reason_required if {
	c := fixture.with_exception_field(fixture.contract, "R4", {"reason": ""})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["exception/reason-required"]
}

test_exception_expiry_required if {
	c := fixture.with_exception_field(fixture.contract, "R4", {"expiresOn": "2026-13-01"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["exception/expiry-required"]
}

test_exception_ttl_expired if {
	c := fixture.with_exception_field(fixture.contract, "R4", {"expiresOn": "2026-10-19"})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["exception/ttl-expired"]
}

test_exception_ttl_expires_today_flags if {
	c := fixture.with_exception_field(fixture.contract, "R4", {"expiresOn": fixture.today})
	r := segment.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["exception/ttl-expired"]
}

test_live_exception_not_flagged if {
	r := segment.validate with input as fixture.validate_input(fixture.contract)
	not error_rules(r)["exception/ttl-expired"]
}

# --- lib parity: the date helpers are a verbatim copy of the estate lib ------

test_epoch_is_day_zero if {
	segment.lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	segment.lib.date_to_days("2026-10-20") - segment.lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not segment.lib.is_valid_date("2026-02-30")
}

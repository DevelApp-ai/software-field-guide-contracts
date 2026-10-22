package authz.policy_test

import rego.v1

import data.authz

import data.authz.fixture

today := "2026-10-20"

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

# Replace version 2's rule list (the most common mutation in these tests).
with_v2_rules(ps, rules) := object.union(ps, {
	"versions": [fixture.policy_set.versions[0], object.union(fixture.policy_set.versions[1], {"rules": rules})],
})

probes_with(extra) := array.concat(fixture.policy_set.probes, extra)

test_valid_set_passes if {
	r := authz.validate with input as {"policySet": fixture.policy_set, "today": today}
	r.valid == true
	count(r.findings) == 0
}

test_input_must_be_object if {
	r := authz.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := authz.validate with input as {"policySet": fixture.policy_set, "today": "yesterday"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_missing_policy_set if {
	r := authz.validate with input as {"today": today}
	not r.valid
	error_rules(r)["policyset/missing"]
}

test_name_required if {
	ps := object.remove(fixture.policy_set, ["name"])
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/name-required"]
}

test_current_version_missing if {
	ps := object.remove(fixture.policy_set, ["currentVersion"])
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/current-version-missing"]
}

test_current_version_not_integer if {
	ps := object.union(fixture.policy_set, {"currentVersion": 2.5})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/current-version-not-integer"]
}

test_current_version_unknown if {
	ps := object.union(fixture.policy_set, {"currentVersion": 99})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/current-version-unknown"]
}

test_current_version_not_yet_effective if {
	r := authz.validate with input as {"policySet": fixture.policy_set, "today": "2026-06-30"}
	not r.valid
	error_rules(r)["policyset/current-version-not-yet-effective"]
}

test_current_version_stale_is_a_warning if {
	r := authz.validate with input as {"policySet": fixture.policy_set, "today": "2027-12-01"}
	r.valid == true
	warning_rules(r)["policyset/current-version-stale"]
}

test_disabled_not_boolean if {
	ps := object.union(fixture.policy_set, {"disabled": "yes"})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/disabled-not-boolean"]
}

test_disabled_is_a_warning_and_stays_valid if {
	r := authz.validate with input as {"policySet": fixture.disabled_set, "today": today}
	r.valid == true
	warning_rules(r)["policyset/disabled"]
}

test_disabled_set_skips_probe_self_check if {
	# The probe 'clerk-read-ok' expects allow, which a disabled set can
	# never answer — so the self-check must be skipped, not fired.
	r := authz.validate with input as {"policySet": fixture.disabled_set, "today": today}
	not error_rules(r)["policyset/probe-expectation-mismatch"]
}

test_subjects_must_be_array if {
	ps := object.remove(fixture.policy_set, ["subjects"])
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/subjects-must-be-array"]
}

test_subject_id_duplicate if {
	ps := object.union(fixture.policy_set, {
		"subjects": array.concat(fixture.policy_set.subjects, [{"id": "bob", "roles": [], "flags": []}]),
	})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/subject-id-duplicate"]
}

test_subject_role_invalid if {
	ps := object.union(fixture.policy_set, {
		"subjects": [{"id": "bob", "roles": [42], "flags": []}],
	})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/subject-role-invalid"]
}

test_versions_required if {
	ps := object.union(fixture.policy_set, {"versions": []})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/versions-required"]
}

test_version_number_duplicate if {
	ps := object.union(fixture.policy_set, {
		"versions": array.concat(fixture.policy_set.versions, [fixture.policy_set.versions[1]]),
	})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/version-number-duplicate"]
}

test_effective_from_invalid if {
	ps := object.union(fixture.policy_set, {
		"versions": [object.union(fixture.policy_set.versions[0], {"effectiveFrom": "2026-2-30"}), fixture.policy_set.versions[1]],
	})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/effective-from-invalid"]
}

test_effective_to_before_from if {
	ps := object.union(fixture.policy_set, {
		"versions": [object.union(fixture.policy_set.versions[0], {"effectiveTo": "2025-12-31"}), fixture.policy_set.versions[1]],
	})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/effective-to-before-from"]
}

test_version_overlap if {
	ps := object.union(fixture.policy_set, {
		"versions": [object.union(fixture.policy_set.versions[0], {"effectiveTo": "2026-08-15"}), fixture.policy_set.versions[1]],
	})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/version-overlap"]
}

test_version_with_no_rules_is_a_warning if {
	# An empty version denies everything in it — that is a legitimate
	# fail-closed state, so it warns rather than errors. The probes are
	# emptied with it, or their expectations would (correctly) mismatch.
	ps := with_v2_rules(object.union(fixture.policy_set, {"probes": []}), [])
	r := authz.validate with input as {"policySet": ps, "today": today}
	r.valid == true
	warning_rules(r)["policyset/version-has-no-rules"]
	warning_rules(r)["policyset/probes-empty"]
}

test_rule_id_duplicate_within_version if {
	rules := array.concat(fixture.policy_set.versions[1].rules, [
		{"id": "clerk-read", "effect": "deny", "subject": {"id": "bob"}, "action": "*", "resource": "*"},
	])
	ps := with_v2_rules(fixture.policy_set, rules)
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/rule-id-duplicate"]
}

test_rule_effect_invalid if {
	rules := array.concat(fixture.policy_set.versions[1].rules, [
		{"id": "maybe-read", "effect": "maybe", "subject": {"role": "clerk"}, "action": "order.read", "resource": "orders-*"},
	])
	ps := with_v2_rules(fixture.policy_set, rules)
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/rule-effect-invalid"]
}

test_rule_subject_ambiguous if {
	rules := array.concat(fixture.policy_set.versions[1].rules, [
		{"id": "either-or", "effect": "allow", "subject": {"id": "bob", "role": "clerk"}, "action": "order.read", "resource": "orders-*"},
	])
	ps := with_v2_rules(fixture.policy_set, rules)
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/rule-subject-ambiguous"]
}

test_rule_subject_missing_keys if {
	rules := array.concat(fixture.policy_set.versions[1].rules, [
		{"id": "nobody", "effect": "allow", "subject": {}, "action": "order.read", "resource": "orders-*"},
	])
	ps := with_v2_rules(fixture.policy_set, rules)
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/rule-subject-required"]
}

test_rule_action_wildcard_invalid if {
	rules := array.concat(fixture.policy_set.versions[1].rules, [
		{"id": "star-mid", "effect": "allow", "subject": {"role": "clerk"}, "action": "order.*.read", "resource": "orders-*"},
	])
	ps := with_v2_rules(fixture.policy_set, rules)
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/rule-action-wildcard-invalid"]
}

test_rule_condition_value_invalid if {
	rules := array.concat(fixture.policy_set.versions[1].rules, [
		{"id": "cond-bad", "effect": "allow", "subject": {"role": "clerk"}, "action": "order.read", "resource": "orders-*", "condition": {"amount": [1]}},
	])
	ps := with_v2_rules(fixture.policy_set, rules)
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/rule-condition-value-invalid"]
}

test_probes_empty_is_a_warning if {
	ps := object.union(fixture.policy_set, {"probes": []})
	r := authz.validate with input as {"policySet": ps, "today": today}
	r.valid == true
	warning_rules(r)["policyset/probes-empty"]
}

test_probe_subject_unknown if {
	ps := object.union(fixture.policy_set, {"probes": probes_with([
		{"id": "ghost-probe", "subject": "ghost", "action": "order.read", "resource": "orders-1041", "expect": "allow"},
	])})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/probe-subject-unknown"]
}

test_probe_id_duplicate if {
	ps := object.union(fixture.policy_set, {"probes": probes_with([
		{"id": "clerk-read-ok", "subject": "alice", "action": "order.read", "resource": "orders-1041", "expect": "allow"},
	])})
	r := authz.validate with input as {"policySet": ps, "today": today}
	not r.valid
	error_rules(r)["policyset/probe-id-duplicate"]
}

flipped_probe_set := object.union(fixture.policy_set, {"probes": [
	object.union(fixture.policy_set.probes[0], {"expect": "deny"}),
	fixture.policy_set.probes[1],
	fixture.policy_set.probes[2],
	fixture.policy_set.probes[3],
]})

test_probe_expectation_mismatch if {
	r := authz.validate with input as {"policySet": flipped_probe_set, "today": today}
	not r.valid
	error_rules(r)["policyset/probe-expectation-mismatch"]
}

test_probe_expectation_mismatch_names_the_probe if {
	r := authz.validate with input as {"policySet": flipped_probe_set, "today": today}
	some f in r.findings
	f.rule == "policyset/probe-expectation-mismatch"
	contains(f.message, "clerk-read-ok")
	f.path == "$.policySet.probes[0].expect"
}

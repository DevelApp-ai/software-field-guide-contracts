package authz.decide_test

import rego.v1

import data.authz

import data.authz.fixture

# Version 2 with extra rules appended (the most common mutation here).
v2_with(extra) := object.union(fixture.policy_set, {
	"versions": [fixture.policy_set.versions[0], object.union(fixture.policy_set.versions[1], {
		"rules": array.concat(fixture.policy_set.versions[1].rules, extra),
	})],
})

trace_step(r, n) := s if {
	s := r.trace[n - 1]
	s.step == n
}

test_allow if {
	r := authz.decide with input as {"request": fixture.request("bob", "order.read", "orders-1041"), "policySet": fixture.policy_set}
	r.decision == "allow"
	r.rule == "clerk-read"
}

test_default_deny if {
	r := authz.decide with input as {"request": fixture.request("bob", "order.delete", "orders-1041"), "policySet": fixture.policy_set}
	r.decision == "deny"
	r.rule == "policy/default-deny"
}

test_deny_beats_allow if {
	ps := v2_with([
		{"id": "bob-frozen", "effect": "deny", "subject": {"id": "bob"}, "action": "*", "resource": "*"},
	])
	r := authz.decide with input as {"request": fixture.request("bob", "order.read", "orders-1041"), "policySet": ps}
	r.decision == "deny"
	r.rule == "bob-frozen"

	# The allow rule matched too — the trace must show both, with deny winning.
	some s in r.trace
	s.rule == "clerk-read"
	s.outcome == "matched"
}

test_fired_rule_is_first_by_id if {
	# Both allow rules match alice; the alphabetically-first id is reported.
	ps := v2_with([
		{"id": "zzz-admin-read", "effect": "allow", "subject": {"role": "admin"}, "action": "order.read", "resource": "orders-*"},
		{"id": "aaa-admin-read", "effect": "allow", "subject": {"role": "admin"}, "action": "order.read", "resource": "orders-*"},
	])
	r := authz.decide with input as {"request": fixture.request("alice", "order.read", "orders-1041"), "policySet": ps}
	r.decision == "allow"
	r.rule == "aaa-admin-read"
}

test_condition_not_met if {
	req := fixture.request_with("bob", "order.charge", "orders-1041", {"mfa": false})
	r := authz.decide with input as {"request": req, "policySet": fixture.policy_set}
	r.decision == "deny"
	r.rule == "policy/default-deny"
	some s in r.trace
	s.rule == "clerk-charge-mfa"
	s.outcome == "not-matched"
	contains(s.because, "condition context.mfa=true is not met")
}

test_condition_met if {
	req := fixture.request_with("bob", "order.charge", "orders-1041", {"mfa": true})
	r := authz.decide with input as {"request": req, "policySet": fixture.policy_set}
	r.decision == "allow"
	r.rule == "clerk-charge-mfa"
}

test_wildcard_action_and_resource if {
	r := authz.decide with input as {"request": fixture.request("alice", "order.delete", "anything"), "policySet": fixture.policy_set}
	r.decision == "allow"
	r.rule == "admin-override"
}

test_unknown_subject_fails_closed if {
	r := authz.decide with input as {"request": fixture.request("ghost", "order.read", "orders-1041"), "policySet": fixture.policy_set}
	r.decision == "deny"
	r.rule == "policy/default-deny"
	s := trace_step(r, 1)
	contains(s.summary, "not in the registry")
}

test_offboarded_deny_fires if {
	r := authz.decide with input as {"request": fixture.request("carol", "order.read", "orders-1041"), "policySet": fixture.policy_set}
	r.decision == "deny"
	r.rule == "offboarded-deny"
}

test_disabled_fails_closed if {
	r := authz.decide with input as {"request": fixture.request("bob", "order.read", "orders-1041"), "policySet": fixture.disabled_set}
	r.decision == "deny"
	r.rule == "policy/disabled-fail-closed"
}

test_missing_version_fails_closed if {
	ps := object.union(fixture.policy_set, {"currentVersion": 99})
	r := authz.decide with input as {"request": fixture.request("bob", "order.read", "orders-1041"), "policySet": ps}
	r.decision == "deny"
	r.rule == "policy/version-missing-fail-closed"
}

test_malformed_input_fails_closed if {
	r := authz.decide with input as [1, 2]
	r.decision == "deny"
	r.rule == "policy/invalid-fail-closed"
}

test_malformed_request_fails_closed if {
	r := authz.decide with input as {"request": {"subject": "bob"}, "policySet": fixture.policy_set}
	r.decision == "deny"
	r.rule == "policy/invalid-fail-closed"
}

test_malformed_policy_set_fails_closed if {
	r := authz.decide with input as {"request": fixture.request("bob", "order.read", "orders-1041"), "policySet": 42}
	r.decision == "deny"
	r.rule == "policy/invalid-fail-closed"
}

test_malformed_rule_is_skipped if {
	ps := v2_with([
		{"id": "broken-rule", "subject": {"role": "clerk"}},
	])
	r := authz.decide with input as {"request": fixture.request("bob", "order.read", "orders-1041"), "policySet": ps}
	r.decision == "allow"
	r.rule == "clerk-read"
	some s in r.trace
	s.rule == "(malformed)"
	s.outcome == "skipped"
}

test_trace_explains_a_403_with_evidence if {
	# The retrospective question this tool must answer from the policy set
	# alone: bob tried to charge order-1041 without MFA and got a 403.
	req := fixture.request_with("bob", "order.charge", "orders-1041", {"mfa": false})
	r := authz.decide with input as {"request": req, "policySet": fixture.policy_set}
	r.decision == "deny"
	first := trace_step(r, 1)
	first.kind == "request"
	contains(first.summary, "subject=bob")
	contains(first.summary, "roles=[clerk]")
	last := trace_step(r, count(r.trace))
	last.kind == "decision"
	last.decision == "deny"
	last.rule == "policy/default-deny"
}

test_trace_is_deterministic if {
	req := fixture.request("bob", "order.read", "orders-1041")
	a := authz.decide with input as {"request": req, "policySet": fixture.policy_set}
	b := authz.decide with input as {"request": req, "policySet": fixture.policy_set}
	a == b
	count(a.trace) == 6
}

test_decide_request_is_a_pure_function if {
	# disabled_check and the probe self-check call this directly; no global
	# input may leak in.
	r := authz.decide_request(fixture.request("bob", "order.read", "orders-1041"), fixture.policy_set)
	r.decision == "allow"
	r.rule == "clerk-read"
}

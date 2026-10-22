package authz.disabled_test

import rego.v1

import data.authz

import data.authz.fixture

# A deliberately broken decision engine: with the policy set disabled it
# still answers allow. disabled_check must catch that, not bless it.
broken_decider(req, ps) := {
	"decision": "allow",
	"rule": "silent-permit",
	"trace": [],
}

test_inventory_matches_the_probes if {
	r := authz.disabled_tests with input as {"policySet": fixture.policy_set}
	r.valid == true
	count(r.tests) == 4
	some t in r.tests
	t.id == "disabled/clerk-read-ok"
	t.expect == "deny"
	t.request.subject == "bob"
	some other in r.tests
	other.id == "disabled/admin-anything"
	other.expect == "deny"
}

test_inventory_is_sorted_by_probe_id if {
	r := authz.disabled_tests with input as {"policySet": fixture.policy_set}
	ids := [t.id | some _, t in r.tests]
	ids == ["disabled/admin-anything", "disabled/clerk-charge-no-mfa", "disabled/clerk-read-ok", "disabled/offboarded-read"]
}

test_disabled_check_proves_deny_not_silent_permit if {
	# Two of these probes expect allow in normal operation; against the
	# disabled set they must come back deny by the fail-closed rule. That
	# is the whole point: deny is proven, never silently permitted.
	r := authz.disabled_check with input as {"policySet": fixture.policy_set}
	r.valid == true
	r.checked == 4
	r.failures == []
	count(r.passing) == 4
	some p in r.passing
	p == "clerk-read-ok"
}

test_disabled_check_reports_a_broken_engine if {
	# Mock the decision engine to silently permit: every probe becomes a
	# failure, and the disabled-state check must say so loudly.
	r := authz.disabled_check with input as {"policySet": fixture.policy_set} with data.authz.decide_request as broken_decider
	not r.valid
	r.checked == 4
	count(r.failures) == 4
	some f in r.failures
	f.probe == "clerk-read-ok"
	f.decision == "allow"
	f.rule == "silent-permit"
}

test_no_probes_is_not_a_pass if {
	ps := object.union(fixture.policy_set, {"probes": []})
	r := authz.disabled_check with input as {"policySet": ps}
	not r.valid
	r.checked == 0
	some f in r.findings
	f.rule == "probes/none"
}

test_missing_policy_set if {
	r := authz.disabled_check with input as {}
	not r.valid
	some f in r.findings
	f.rule == "policyset/missing"
}

test_inventory_missing_policy_set if {
	r := authz.disabled_tests with input as {}
	not r.valid
	some f in r.findings
	f.rule == "policyset/missing"
}

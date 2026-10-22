package authz.retro_test

import rego.v1

import data.authz

import data.authz.fixture

# Version 2 with extra rules appended.
v2_with(extra) := object.union(fixture.policy_set, {
	"versions": [fixture.policy_set.versions[0], object.union(fixture.policy_set.versions[1], {
		"rules": array.concat(fixture.policy_set.versions[1].rules, extra),
	})],
})

test_full_history_answers_who_could_read if {
	r := authz.who_could_access with input as {
		"resource": "orders-1041",
		"action": "order.read",
		"window": {"from": "2026-01-01", "to": "2026-12-31"},
		"policySet": fixture.policy_set,
	}
	r.valid == true
	r.subjects == ["alice", "bob"]
	count(r.grants) == 3
	some g in r.grants
	g == {"subject": "bob", "version": 1, "rule": "clerk-read-v1", "action": "order.read", "resource": "orders-*"}
}

test_window_limited_to_version_one if {
	r := authz.who_could_access with input as {
		"resource": "orders-1041",
		"action": "order.read",
		"window": {"from": "2026-01-01", "to": "2026-06-30"},
		"policySet": fixture.policy_set,
	}
	r.valid == true
	r.subjects == ["bob"]
	count(r.grants) == 1
	r.grants[0].version == 1
	r.grants[0].rule == "clerk-read-v1"
}

test_absent_action_means_any_action if {
	r := authz.who_could_access with input as {
		"resource": "orders-1041",
		"window": {"from": "2026-07-01", "to": "2026-12-31"},
		"policySet": fixture.policy_set,
	}
	r.valid == true
	r.subjects == ["alice", "bob"]

	# bob shows once per version (clerk-read), alice once (admin-override).
	count(r.grants) == 3
	some g in r.grants
	g.subject == "alice"
	g.rule == "admin-override"
}

test_empty_action_string_means_any_action if {
	r := authz.who_could_access with input as {
		"resource": "orders-1041",
		"action": "",
		"window": {"from": "2026-07-01", "to": "2026-12-31"},
		"policySet": fixture.policy_set,
	}
	r.valid == true
	r.subjects == ["alice", "bob"]
}

test_deny_excludes_a_granted_subject if {
	ps := v2_with([
		{"id": "clerk-read-revoked", "effect": "deny", "subject": {"role": "clerk"}, "action": "order.read", "resource": "orders-*"},
	])
	r := authz.who_could_access with input as {
		"resource": "orders-1041",
		"action": "order.read",
		"window": {"from": "2026-07-01", "to": "2026-12-31"},
		"policySet": ps,
	}
	r.valid == true
	r.subjects == ["alice"]
}

test_wildcard_grant_covers_every_resource if {
	# admin-override is action "*" resource "*": it answers for reports
	# too, and the retrospective answer must say so instead of silently
	# dropping the grant.
	r := authz.who_could_access with input as {
		"resource": "reports-q3",
		"action": "report.read",
		"window": {"from": "2026-01-01", "to": "2026-12-31"},
		"policySet": fixture.policy_set,
	}
	r.valid == true
	r.subjects == ["alice"]
	some g in r.grants
	g.rule == "admin-override"
}

test_inverted_window_is_invalid if {
	r := authz.who_could_access with input as {
		"resource": "orders-1041",
		"action": "order.read",
		"window": {"from": "2026-12-31", "to": "2026-01-01"},
		"policySet": fixture.policy_set,
	}
	not r.valid
	r.subjects == []
	some f in r.findings
	f.rule == "retro/window-inverted"
}

test_missing_resource_is_invalid if {
	r := authz.who_could_access with input as {
		"window": {"from": "2026-01-01", "to": "2026-12-31"},
		"policySet": fixture.policy_set,
	}
	not r.valid
	some f in r.findings
	f.rule == "retro/resource-required"
}

test_missing_policy_set_is_invalid if {
	r := authz.who_could_access with input as {
		"resource": "orders-1041",
		"window": {"from": "2026-01-01", "to": "2026-12-31"},
	}
	not r.valid
	some f in r.findings
	f.rule == "retro/policyset-missing"
}

test_offboarded_subject_never_appears if {
	# carol carries the offboarded flag: no allow rule names her in the
	# first place, so no window can grant her anything.
	r := authz.who_could_access with input as {
		"resource": "orders-1041",
		"action": "order.read",
		"window": {"from": "2026-01-01", "to": "2026-12-31"},
		"policySet": fixture.policy_set,
	}
	not "carol" in r.subjects
}

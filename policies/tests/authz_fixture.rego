# Shared fixture for the authz tests: one small, valid policy set in the
# checkout/payments flavor of the book's examples — a registry, a two-step
# version history, and probes that pin down what the set must answer.
#
# The version dates and the probe expectations are chosen relative to the
# CI anchor date 2026-10-20 (see Makefile and .github/workflows/ci.yml).
package authz.fixture

import rego.v1

policy_set := {
	"name": "storefront",
	"currentVersion": 2,
	"subjects": [
		{"id": "alice", "roles": ["admin"], "flags": ["mfa-verified"]},
		{"id": "bob", "roles": ["clerk"], "flags": []},
		{"id": "carol", "roles": [], "flags": ["offboarded"]},
	],
	"versions": [
		{
			"version": 1,
			"effectiveFrom": "2026-01-01",
			"effectiveTo": "2026-06-30",
			"rules": [
				{"id": "clerk-read-v1", "effect": "allow", "subject": {"role": "clerk"}, "action": "order.read", "resource": "orders-*"},
			],
		},
		{
			"version": 2,
			"effectiveFrom": "2026-07-01",
			"rules": [
				{"id": "clerk-read", "effect": "allow", "subject": {"role": "clerk"}, "action": "order.read", "resource": "orders-*"},
				{"id": "clerk-charge-mfa", "effect": "allow", "subject": {"role": "clerk"}, "action": "order.charge", "resource": "orders-*", "condition": {"mfa": true}},
				{"id": "admin-override", "effect": "allow", "subject": {"role": "admin"}, "action": "*", "resource": "*"},
				{"id": "offboarded-deny", "effect": "deny", "subject": {"flag": "offboarded"}, "action": "*", "resource": "*"},
			],
		},
	],
	"probes": [
		{"id": "clerk-read-ok", "subject": "bob", "action": "order.read", "resource": "orders-1041", "context": {}, "expect": "allow"},
		{"id": "clerk-charge-no-mfa", "subject": "bob", "action": "order.charge", "resource": "orders-1041", "context": {"mfa": false}, "expect": "deny"},
		{"id": "offboarded-read", "subject": "carol", "action": "order.read", "resource": "orders-1041", "expect": "deny"},
		{"id": "admin-anything", "subject": "alice", "action": "order.export", "resource": "orders-1041", "expect": "allow"},
	],
}

disabled_set := object.union(policy_set, {"disabled": true})

# A request builder for the decision tests.
request(subject, action, resource) := {
	"subject": subject,
	"action": action,
	"resource": resource,
	"context": {},
}

# A request builder carrying context (for conditioned rules).
request_with(subject, action, resource, context) := {
	"subject": subject,
	"action": action,
	"resource": resource,
	"context": context,
}

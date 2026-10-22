# Disabled-state fail-closed tests — The Software Field Guide, issue #59.
#
# The probes in a policy set are expectations about the current version.
# Flipped the other way, they are the inventory for the question that
# matters when someone switches authorization off: with the whole policy
# set disabled, does every one of those requests come back deny — or does
# something silently permit?
#
# `disabled_tests` generates the inventory from the policy set's probes:
# one fail-closed test per probe, each expecting deny.
# `disabled_check` runs them: it evaluates every probe against the
# disabled variant of the set and fails loudly unless each answer is
# deny by the named rule `policy/disabled-fail-closed`. Deny is proven,
# never assumed.
#
# Input (JSON):  {"policySet": {...}}
# Results:       disabled_tests: {"valid", "tests": [...], "findings": [...]}
#                disabled_check: {"valid", "checked", "failures", "passing", "findings"}
package authz

import rego.v1

# --- the generated inventory ------------------------------------------------

disabled_tests := result if {
	fs := sort([f | disabled_findings[f]])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"tests": [disabled_test_for(policy_set, id) |
			some id in sort([object.get(p, "id", null) | some p in probes_ok(policy_set)])
		],
		"findings": fs,
	}
}

disabled_test_for(ps, id) := test if {
	some p in probes_ok(ps)
	object.get(p, "id", null) == id
	test := {
		"id": sprintf("disabled/%s", [id]),
		"request": probe_request(p),
		"expect": "deny",
		"because": "the policy set is disabled: every request must fail closed, never silently permit",
	}
}

# --- running the generated tests -----------------------------------------------

disabled_check := result if {
	not is_object(policy_set)
	result := {
		"valid": false,
		"checked": 0,
		"failures": [],
		"passing": [],
		"findings": [{
			"severity": "error",
			"rule": "policyset/missing",
			"message": "policySet is missing or not an object",
			"path": "$.policySet",
		}],
	}
}

disabled_check := result if {
	is_object(policy_set)
	probes := probes_ok(policy_set)
	count(probes) == 0
	result := {
		"valid": false,
		"checked": 0,
		"failures": [],
		"passing": [],
		"findings": [{
			"severity": "error",
			"rule": "probes/none",
			"message": "the policy set declares no usable probes: there is nothing to prove fail-closed with",
			"path": "$.policySet.probes",
		}],
	}
}

disabled_check := result if {
	is_object(policy_set)
	probes := probes_ok(policy_set)
	count(probes) > 0
	disabled_set := object.union(policy_set, {"disabled": true})
	outcomes := [disabled_outcome_for(p, disabled_set) | some p in probes]
	failures := sort([o | some o in outcomes; not disabled_outcome_ok(o)])
	result := {
		"valid": count(failures) == 0,
		"checked": count(probes),
		"failures": failures,
		"passing": sort([o.probe | some o in outcomes; disabled_outcome_ok(o)]),
		"findings": [],
	}
}

disabled_outcome_for(p, disabled_set) := o if {
	d := decide_request(probe_request(p), disabled_set)
	o := {
		"probe": object.get(p, "id", null),
		"decision": d.decision,
		"rule": d.rule,
		"trace": d.trace,
	}
}

disabled_outcome_ok(o) if {
	o.decision == "deny"
	o.rule == "policy/disabled-fail-closed"
}

# --- findings -------------------------------------------------------------------

disabled_findings contains finding if {
	is_object(input)
	not is_object(policy_set)
	finding := {
		"severity": "error",
		"rule": "policyset/missing",
		"message": "policySet is missing or not an object",
		"path": "$.policySet",
	}
}

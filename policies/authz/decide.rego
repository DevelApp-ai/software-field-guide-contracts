# Authorization decision explainer — The Software Field Guide, issue #59.
#
# `decide` answers one request (subject, action, resource, context) against
# a policy set and returns a deterministic decision trace: which rules were
# considered, which fired, which criterion each non-firing rule failed on,
# and the rule that decided the outcome. Explicit deny beats allow; among
# the rules that fire, the alphabetically-first id is reported; nothing
# matching means default deny. Every failure mode — malformed input, a
# disabled policy set, a missing current version — fails closed with its
# own named rule, so a 403 always comes with its explanation.
#
# Input (JSON):  {"request": {"subject", "action", "resource", "context"?},
#                 "policySet": {...}}
# Result:        {"decision": "allow"|"deny", "rule": <rule id>, "trace": [...]}
package authz

import rego.v1

import data.authz.lib

# --- entrypoint -------------------------------------------------------------

default decide := {
	"decision": "deny",
	"rule": "policy/invalid-fail-closed",
	"trace": [
		{
			"step": 1,
			"kind": "input",
			"because": "input must be an object with a policySet object and a request object (subject, action, resource — non-empty strings)",
		},
		{
			"step": 2,
			"kind": "decision",
			"decision": "deny",
			"rule": "policy/invalid-fail-closed",
			"because": "malformed input fails closed — the engine never errors and never guesses",
		},
	],
}

decide := result if {
	is_object(input)
	req := object.get(input, "request", null)
	ps := object.get(input, "policySet", null)
	request_well_formed(req)
	is_object(ps)
	result := decide_request(req, ps)
}

# --- the decision -----------------------------------------------------------

decide_request(req, ps) := result if {
	ps_disabled(ps)
	result := {
		"decision": "deny",
		"rule": "policy/disabled-fail-closed",
		"trace": [
			{"step": 1, "kind": "request", "summary": request_summary(req, ps), "version": null},
			{"step": 2, "kind": "policy", "because": "the policy set is marked disabled: every request fails closed"},
			{
				"step": 3,
				"kind": "decision",
				"decision": "deny",
				"rule": "policy/disabled-fail-closed",
				"because": "a disabled policy set denies by construction",
			},
		],
	}
}

decide_request(req, ps) := result if {
	not ps_disabled(ps)
	version := active_version(ps)
	result := evaluate_request(req, ps, version)
}

decide_request(req, ps) := result if {
	not ps_disabled(ps)
	not has_active_version(ps)
	result := {
		"decision": "deny",
		"rule": "policy/version-missing-fail-closed",
		"trace": [
			{"step": 1, "kind": "request", "summary": request_summary(req, ps), "version": null},
			{
				"step": 2,
				"kind": "policy",
				"because": sprintf("currentVersion %v does not name a declared version, so no rule set is active", [object.get(ps, "currentVersion", null)]),
			},
			{
				"step": 3,
				"kind": "decision",
				"decision": "deny",
				"rule": "policy/version-missing-fail-closed",
				"because": "with no active version no rule can fire: fail closed",
			},
		],
	}
}

ps_disabled(ps) if {
	is_object(ps)
	object.get(ps, "disabled", false) == true
}

has_active_version(ps) if {
	active_version(ps)
}

active_version(ps) := v if {
	is_object(ps)
	matches := [v |
		some v in object.get(ps, "versions", [])
		is_object(v)
		object.get(v, "version", null) == object.get(ps, "currentVersion", null)
	]
	count(matches) > 0
	v := matches[0]
}

# --- evaluating one request against one active version ------------------------

evaluate_request(req, ps, version) := result if {
	steps := [rule_step(req, r, ps) | some r in version_rules(version)]
	deny_ids := sort([s.rule | some s in steps; s.outcome == "matched"; s.effect == "deny"])
	allow_ids := sort([s.rule | some s in steps; s.outcome == "matched"; s.effect == "allow"])
	fired := fired_rule(deny_ids, allow_ids)
	result := {
		"decision": fired.decision,
		"rule": fired.rule,
		"trace": trace_steps(req, ps, version, steps, fired),
	}
}

fired_rule(deny_ids, allow_ids) := {
	"decision": "deny",
	"rule": deny_ids[0],
	"because": "an explicit deny rule fired: deny beats allow",
} if {
	count(deny_ids) > 0
}

fired_rule(deny_ids, allow_ids) := {
	"decision": "allow",
	"rule": allow_ids[0],
	"because": "allow rule fired and no deny rule did",
} if {
	count(deny_ids) == 0
	count(allow_ids) > 0
}

fired_rule(deny_ids, allow_ids) := {
	"decision": "deny",
	"rule": "policy/default-deny",
	"because": "no rule matched: default deny",
} if {
	count(deny_ids) == 0
	count(allow_ids) == 0
}

# --- per-rule trace steps -------------------------------------------------------

rule_step(req, r, ps) := {
	"rule": "(malformed)",
	"effect": "-",
	"outcome": "skipped",
	"because": "rule is malformed (missing id, effect, subject, action, or resource) and was skipped",
} if {
	not usable_rule(r)
}

rule_step(req, r, ps) := {
	"rule": rule_id(r),
	"effect": rule_effect(r),
	"outcome": "not-matched",
	"because": rule_mismatch_reason(req, r, ps),
} if {
	usable_rule(r)
	not rule_fully_matches(req, r, ps)
}

rule_step(req, r, ps) := {
	"rule": rule_id(r),
	"effect": rule_effect(r),
	"outcome": "matched",
	"because": rule_match_reason(req, r, ps),
} if {
	usable_rule(r)
	rule_fully_matches(req, r, ps)
}

rule_fully_matches(req, r, ps) if {
	condition_of(r) == null
	selector_matches(object.get(r, "subject", null), ps, request_subject(req))
	lib.wildcard_match(rule_action(r), request_action(req))
	lib.wildcard_match(rule_resource(r), request_resource(req))
}

rule_fully_matches(req, r, ps) if {
	cond := condition_of(r)
	cond != null
	selector_matches(object.get(r, "subject", null), ps, request_subject(req))
	lib.wildcard_match(rule_action(r), request_action(req))
	lib.wildcard_match(rule_resource(r), request_resource(req))
	condition_satisfied(cond, request_context(req))
}

# --- why a rule did or did not fire ---------------------------------------------

rule_match_reason(req, r, ps) := reason if {
	sel := object.get(r, "subject", null)
	reason := sprintf("all criteria matched (subject.%s=%s; action %s; resource %s; condition %s)", [
		selector_key(sel),
		object.get(sel, selector_key(sel), null),
		rule_action(r),
		rule_resource(r),
		condition_note(r),
	])
}

condition_note(r) := "absent" if {
	condition_of(r) == null
}

condition_note(r) := "met" if {
	condition_of(r) != null
}

rule_mismatch_reason(req, r, ps) := reason if {
	sel := object.get(r, "subject", null)
	not selector_matches(sel, ps, request_subject(req))
	reason := sprintf("subject %s does not match subject.%s=%s (%s)", [
		request_subject(req),
		selector_key(sel),
		object.get(sel, selector_key(sel), null),
		subject_evidence(ps, request_subject(req)),
	])
}

rule_mismatch_reason(req, r, ps) := reason if {
	sel := object.get(r, "subject", null)
	selector_matches(sel, ps, request_subject(req))
	not lib.wildcard_match(rule_action(r), request_action(req))
	reason := sprintf("action %s does not match pattern %s", [request_action(req), rule_action(r)])
}

rule_mismatch_reason(req, r, ps) := reason if {
	sel := object.get(r, "subject", null)
	selector_matches(sel, ps, request_subject(req))
	lib.wildcard_match(rule_action(r), request_action(req))
	not lib.wildcard_match(rule_resource(r), request_resource(req))
	reason := sprintf("resource %s does not match pattern %s", [request_resource(req), rule_resource(r)])
}

rule_mismatch_reason(req, r, ps) := reason if {
	sel := object.get(r, "subject", null)
	selector_matches(sel, ps, request_subject(req))
	lib.wildcard_match(rule_action(r), request_action(req))
	lib.wildcard_match(rule_resource(r), request_resource(req))
	cond := condition_of(r)
	cond != null
	not condition_satisfied(cond, request_context(req))
	reason := condition_failure(cond, request_context(req))
}

# --- the assembled trace ----------------------------------------------------------

trace_steps(req, ps, version, steps, fired) := trace if {
	head := [{"step": 1, "kind": "request", "summary": request_summary(req, ps), "version": object.get(version, "version", null)}]
	mid := [{"step": i + 2, "kind": "rule", "rule": s.rule, "effect": s.effect, "outcome": s.outcome, "because": s.because} |
		some i, s in steps
	]
	last := [{
		"step": count(steps) + 2,
		"kind": "decision",
		"decision": fired.decision,
		"rule": fired.rule,
		"because": fired.because,
	}]
	trace := array.concat(head, array.concat(mid, last))
}

request_summary(req, ps) := summary if {
	sid := request_subject(req)
	entry_known(ps, sid)
	summary := sprintf("subject=%s roles=[%s] flags=[%s] action=%s resource=%s", [
		sid,
		concat(", ", safe_roles(ps, sid)),
		concat(", ", safe_flags(ps, sid)),
		request_action(req),
		request_resource(req),
	])
}

request_summary(req, ps) := summary if {
	sid := request_subject(req)
	not entry_known(ps, sid)
	summary := sprintf("subject=%s (not in the registry) action=%s resource=%s", [
		sid,
		request_action(req),
		request_resource(req),
	])
}

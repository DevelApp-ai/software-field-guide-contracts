# The policy-set model shared by every authz entry point — The Software
# Field Guide, issue #59.
#
# A policy set is a small, deliberate language, not a general engine:
# a subject registry (ids with roles and flags), a list of rule versions
# with effective dates, and a probe list that pins down what the set is
# expected to answer. The helpers here read that model defensively: every
# accessor guards its input before touching object fields, so a malformed
# document can produce findings and fail-closed decisions but never a
# runtime error — which matters because a WASM evaluation traps on
# builtin errors.
package authz

import rego.v1

import data.authz.lib

# --- requests -------------------------------------------------------------

request_subject(req) := object.get(req, "subject", null)

request_action(req) := object.get(req, "action", null)

request_resource(req) := object.get(req, "resource", null)

request_context(req) := ctx if {
	ctx := object.get(req, "context", {})
	is_object(ctx)
}

request_context(req) := {} if {
	not is_object(object.get(req, "context", {}))
}

request_well_formed(req) if {
	is_object(req)
	lib.is_nonempty_string(request_subject(req))
	lib.is_nonempty_string(request_action(req))
	lib.is_nonempty_string(request_resource(req))
}

# --- numbers ---------------------------------------------------------------

is_integer(v) if {
	is_number(v)
	v == floor(v)
}

# --- patterns (exact or trailing-star) ---------------------------------------

is_pattern(v) if {
	lib.is_nonempty_string(v)
	regex.match(`^[^*]*\*?$`, v)
}

# --- subject registry -------------------------------------------------------

# First registry entry carrying this id, so duplicate ids (the validator
# flags them) can never make a lookup ambiguous here.
registry_entry(ps, sid) := entry if {
	is_object(ps)
	matches := [entry |
		some entry in object.get(ps, "subjects", [])
		is_object(entry)
		object.get(entry, "id", null) == sid
	]
	count(matches) > 0
	entry := matches[0]
}

entry_known(ps, sid) if {
	registry_entry(ps, sid)
}

subject_roles(ps, sid) := roles if {
	entry := registry_entry(ps, sid)
	roles := object.get(entry, "roles", [])
	is_array(roles)
}

subject_roles(ps, sid) := [] if {
	entry := registry_entry(ps, sid)
	not is_array(object.get(entry, "roles", []))
}

subject_roles(ps, sid) := [] if {
	not registry_entry(ps, sid)
}

subject_flags(ps, sid) := flags if {
	entry := registry_entry(ps, sid)
	flags := object.get(entry, "flags", [])
	is_array(flags)
}

subject_flags(ps, sid) := [] if {
	entry := registry_entry(ps, sid)
	not is_array(object.get(entry, "flags", []))
}

subject_flags(ps, sid) := [] if {
	not registry_entry(ps, sid)
}

safe_roles(ps, sid) := [role | some role in subject_roles(ps, sid); is_string(role)]

safe_flags(ps, sid) := [flag | some flag in subject_flags(ps, sid); is_string(flag)]

subject_evidence(ps, sid) := evidence if {
	entry_known(ps, sid)
	evidence := sprintf("roles=[%s], flags=[%s]", [concat(", ", safe_roles(ps, sid)), concat(", ", safe_flags(ps, sid))])
}

subject_evidence(ps, sid) := "not in the registry" if {
	not entry_known(ps, sid)
}

subjects_array(ps) := arr if {
	is_object(ps)
	arr := object.get(ps, "subjects", [])
	is_array(arr)
}

subjects_array(ps) := [] if {
	is_object(ps)
	not is_array(object.get(ps, "subjects", []))
}

subjects_array(ps) := [] if {
	not is_object(ps)
}

registry_ids(ps) := ids if {
	ids := {object.get(e, "id", null) |
		some e in subjects_array(ps)
		is_object(e)
		lib.is_nonempty_string(object.get(e, "id", null))
	}
}

# --- rule subject selectors ---------------------------------------------------

# A selector names exactly one of id, role, or flag. Anything else is
# rejected up front by the validator, so the matchers below never have to
# guess what a selector with two keys would mean.
present_selectors(sel) := ks if {
	is_object(sel)
	ks := [k |
		some k in ["id", "role", "flag"]
		lib.is_nonempty_string(object.get(sel, k, null))
	]
}

present_selectors(sel) := [] if {
	not is_object(sel)
}

selector_valid(sel) if {
	is_object(sel)
	count(present_selectors(sel)) == 1
}

selector_key(sel) := k if {
	ks := present_selectors(sel)
	count(ks) == 1
	k := ks[0]
}

selector_matches(sel, ps, sid) if {
	is_object(sel)
	selector_key(sel) == "id"
	object.get(sel, "id", null) == sid
}

selector_matches(sel, ps, sid) if {
	is_object(sel)
	selector_key(sel) == "role"
	some role in subject_roles(ps, sid)
	role == object.get(sel, "role", null)
}

selector_matches(sel, ps, sid) if {
	is_object(sel)
	selector_key(sel) == "flag"
	some flag in subject_flags(ps, sid)
	flag == object.get(sel, "flag", null)
}

# --- rules --------------------------------------------------------------------

# A usable rule has everything the matcher needs: a name, an effect, a
# single-key selector, and pattern-shaped action and resource. Unusable
# rules are skipped by the decision engine and flagged by the validator.
usable_rule(r) if {
	is_object(r)
	lib.is_nonempty_string(object.get(r, "id", null))
	object.get(r, "effect", null) in {"allow", "deny"}
	selector_valid(object.get(r, "subject", null))
	is_pattern(object.get(r, "action", null))
	is_pattern(object.get(r, "resource", null))
}

rule_action(r) := object.get(r, "action", null)

rule_resource(r) := object.get(r, "resource", null)

rule_effect(r) := object.get(r, "effect", null)

rule_id(r) := object.get(r, "id", null)

# --- conditions ----------------------------------------------------------------

condition_of(r) := cond if {
	cond := object.get(r, "condition", null)
	is_object(cond)
}

condition_of(r) := null if {
	not is_object(object.get(r, "condition", null))
}

condition_satisfied(cond, ctx) if {
	unsatisfied := [k |
		some k, expected in cond
		object.get(ctx, k, null) != expected
	]
	count(unsatisfied) == 0
}

condition_failure(cond, ctx) := reason if {
	unsatisfied := sort([k |
		some k, expected in cond
		object.get(ctx, k, null) != expected
	])
	count(unsatisfied) > 0
	k := unsatisfied[0]
	reason := sprintf("condition context.%s=%v is not met (context has %s=%v)", [
		k,
		object.get(cond, k, null),
		k,
		object.get(ctx, k, null),
	])
}

# --- probes -----------------------------------------------------------------------

probe_well_formed(p) if {
	is_object(p)
	lib.is_nonempty_string(object.get(p, "id", null))
	lib.is_nonempty_string(object.get(p, "subject", null))
	lib.is_nonempty_string(object.get(p, "action", null))
	lib.is_nonempty_string(object.get(p, "resource", null))
	expect_ok(p)
	context_ok(p)
}

expect_ok(p) if {
	object.get(p, "expect", null) in {"allow", "deny"}
}

expect_ok(p) if {
	not is_object(p)
}

context_ok(p) if {
	not is_object(p)
}

context_ok(p) if {
	is_object(p)
	object.get(p, "context", null) == null
}

context_ok(p) if {
	is_object(p)
	is_object(object.get(p, "context", null))
}

probe_request(p) := {
	"subject": object.get(p, "subject", null),
	"action": object.get(p, "action", null),
	"resource": object.get(p, "resource", null),
	"context": request_context(p),
}

probes_array(ps) := arr if {
	is_object(ps)
	arr := object.get(ps, "probes", [])
	is_array(arr)
}

probes_array(ps) := [] if {
	is_object(ps)
	not is_array(object.get(ps, "probes", []))
}

probes_array(ps) := [] if {
	not is_object(ps)
}

probes_ok(ps) := [p |
	some p in probes_array(ps)
	probe_well_formed(p)
]

# --- versions ------------------------------------------------------------------------

version_rules(version) := rules if {
	is_object(version)
	rules := object.get(version, "rules", [])
	is_array(rules)
}

version_rules(version) := [] if {
	is_object(version)
	not is_array(object.get(version, "rules", []))
}

version_rules(version) := [] if {
	not is_object(version)
}

has_effective_to(v) if {
	is_object(v)
	object.get(v, "effectiveTo", null) != null
}

version_from_days(v) := lib.date_to_days(object.get(v, "effectiveFrom", null))

version_to_days(v) := 99999999 if {
	not has_effective_to(v)
}

version_to_days(v) := lib.date_to_days(object.get(v, "effectiveTo", null)) if {
	has_effective_to(v)
}

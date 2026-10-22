# Retrospective access questions — The Software Field Guide, issue #59.
#
# `who_could_access` answers audit questions from the policy set as the
# audit substrate: given a resource (and optionally an action) and a date
# window, which subjects did some allow rule grant, across every version
# effective during that window, minus the subjects a deny rule in the
# same version excluded? Every grant is reported with the evidence —
# the subject, the version, and the rule that carried the grant.
#
# Input (JSON):  {"resource": "...", "action"?: "...",
#                 "window": {"from": "...", "to": "..."}, "policySet": {...}}
# Result:        {"valid": bool, "findings": [...], "subjects": [...], "grants": [...]}
package authz

import rego.v1

import data.authz.lib

# --- input -----------------------------------------------------------------

requested_resource := object.get(input, "resource", null) if is_object(input)

requested_action := object.get(input, "action", null) if is_object(input)

window := object.get(input, "window", null) if is_object(input)

action_given if {
	lib.is_nonempty_string(requested_action)
}

# --- entrypoint ------------------------------------------------------------

who_could_access := result if {
	retro_input_valid
	grants := retro_grants(requested_resource, requested_action, window, policy_set)
	result := {
		"valid": true,
		"findings": [],
		"subjects": sort({g.subject | some g in grants}),
		"grants": grants,
	}
}

who_could_access := result if {
	is_object(input)
	not retro_input_valid
	fs := sort([f | retro_findings[f]])
	result := {
		"valid": false,
		"findings": fs,
		"subjects": [],
		"grants": [],
	}
}

who_could_access := result if {
	not is_object(input)
	result := {
		"valid": false,
		"findings": [{
			"severity": "error",
			"rule": "retro/input-invalid",
			"message": "input must be an object with 'resource', 'window', and 'policySet' fields",
			"path": "$",
		}],
		"subjects": [],
		"grants": [],
	}
}

# --- input shape ------------------------------------------------------------

retro_input_valid if {
	is_object(input)
	lib.is_nonempty_string(requested_resource)
	action_usable
	window_valid
	is_object(policy_set)
}

# An absent action, or an empty string (the CLI default), means "any action".
action_usable if object.get(input, "action", null) == null

action_usable if object.get(input, "action", null) == ""

action_usable if action_given

window_valid if {
	is_object(window)
	lib.is_valid_date(object.get(window, "from", null))
	lib.is_valid_date(object.get(window, "to", null))
	lib.date_to_days(object.get(window, "from", null)) <= lib.date_to_days(object.get(window, "to", null))
}

# --- findings ---------------------------------------------------------------

retro_findings contains finding if {
	is_object(input)
	not lib.is_nonempty_string(requested_resource)
	finding := {
		"severity": "error",
		"rule": "retro/resource-required",
		"message": "resource is required: the audit question names what was accessed",
		"path": "$.resource",
	}
}

retro_findings contains finding if {
	is_object(input)
	object.get(input, "action", null) != null
	not action_usable
	finding := {
		"severity": "error",
		"rule": "retro/action-invalid",
		"message": "action must be a non-empty string, or absent (meaning any action)",
		"path": "$.action",
	}
}

retro_findings contains finding if {
	is_object(input)
	not is_object(window)
	finding := {
		"severity": "error",
		"rule": "retro/window-must-be-object",
		"message": "window must be an object with 'from' and 'to' dates (YYYY-MM-DD)",
		"path": "$.window",
	}
}

retro_findings contains finding if {
	is_object(input)
	is_object(window)
	not lib.is_valid_date(object.get(window, "from", null))
	finding := {
		"severity": "error",
		"rule": "retro/window-from-invalid",
		"message": "window.from must be a valid calendar date in YYYY-MM-DD format",
		"path": "$.window.from",
	}
}

retro_findings contains finding if {
	is_object(input)
	is_object(window)
	not lib.is_valid_date(object.get(window, "to", null))
	finding := {
		"severity": "error",
		"rule": "retro/window-to-invalid",
		"message": "window.to must be a valid calendar date in YYYY-MM-DD format",
		"path": "$.window.to",
	}
}

retro_findings contains finding if {
	is_object(input)
	is_object(window)
	lib.is_valid_date(object.get(window, "from", null))
	lib.is_valid_date(object.get(window, "to", null))
	lib.date_to_days(object.get(window, "from", null)) > lib.date_to_days(object.get(window, "to", null))
	finding := {
		"severity": "error",
		"rule": "retro/window-inverted",
		"message": "window.from lies after window.to: a retrospective window runs forward in time",
		"path": "$.window",
	}
}

retro_findings contains finding if {
	is_object(input)
	not is_object(policy_set)
	finding := {
		"severity": "error",
		"rule": "retro/policyset-missing",
		"message": "policySet is missing or not an object",
		"path": "$.policySet",
	}
}

# --- the retrospective evaluation ---------------------------------------------

# A version answers the question during the window when its effective
# interval (effectiveFrom..effectiveTo, both inclusive) overlaps the
# window. Versions with unusable dates are skipped silently here — the
# validator is the loud gate for those.
version_in_window(v, w) if {
	versions_effective_usable(v)
	version_from_days(v) <= lib.date_to_days(object.get(w, "to", null))
	lib.date_to_days(object.get(w, "from", null)) <= version_to_days(v)
}

retro_grants(resource, action, w, ps) := grants if {
	grants := sort([g |
		some v in object.get(ps, "versions", [])
		version_in_window(v, w)
		some r in version_rules(v)
		usable_rule(r)
		rule_effect(r) == "allow"
		lib.wildcard_match(rule_resource(r), resource)
		grant_action_matches(action, rule_action(r))
		some sid in grant_subjects(r, ps)
		not deny_excludes(ps, v, sid, resource, rule_action(r))
		g := {
			"subject": sid,
			"version": object.get(v, "version", null),
			"rule": rule_id(r),
			"action": rule_action(r),
			"resource": rule_resource(r),
		}
	])
}

grant_action_matches(action, rule_action) if {
	action_given
	lib.wildcard_match(rule_action, action)
}

grant_action_matches(action, rule_action) if {
	not action_given
}

# The subjects an allow rule's selector can name: a direct id, or every
# registry entry carrying the role or flag.
grant_subjects(r, ps) := [object.get(object.get(r, "subject", null), "id", null)] if {
	sel := object.get(r, "subject", null)
	selector_key(sel) == "id"
}

grant_subjects(r, ps) := sids if {
	sel := object.get(r, "subject", null)
	selector_key(sel) == "role"
	sids := grant_subjects_by_field(sel, ps, "roles")
}

grant_subjects(r, ps) := sids if {
	sel := object.get(r, "subject", null)
	selector_key(sel) == "flag"
	sids := grant_subjects_by_field(sel, ps, "flags")
}

# `key` is the registry field ("roles" or "flags"); the selector key is
# read from the rule itself.
grant_subjects_by_field(sel, ps, key) := sids if {
	wanted := object.get(sel, selector_key(sel), null)
	sids := sort({object.get(e, "id", null) |
		some e in subjects_array(ps)
		is_object(e)
		lib.is_nonempty_string(object.get(e, "id", null))
		some v in registry_field_values(e, key)
		v == wanted
	})
}

registry_field_values(e, field) := [v |
	some v in object.get(e, field, [])
	is_string(v)
]

registry_field_values(e, field) := [] if {
	not is_array(object.get(e, field, []))
}

# A deny rule in the same version takes the grant away: same subject,
# same resource, same action.
deny_excludes(ps, v, sid, resource, grant_action) if {
	some d in version_rules(v)
	usable_rule(d)
	rule_effect(d) == "deny"
	selector_matches(object.get(d, "subject", null), ps, sid)
	lib.wildcard_match(rule_resource(d), resource)
	lib.wildcard_match(rule_action(d), grant_action)
}

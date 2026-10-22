# Authorization policy set validator — The Software Field Guide, issue #59.
#
# A policy set is a versioned bundle: a subject registry, a list of rule
# versions with effective dates, and a probe list. This policy judges a
# set before it is ever used to answer a request: ids are unique, effects
# are allow or deny, selectors name exactly one of id/role/flag, wildcards
# are trailing-only, versions do not overlap, the current version exists
# and is in effect, and every probe's expectation is replayed against the
# set itself. The clock is injected as `today`, so the same set validates
# identically in CI, offline, and in the browser.
#
# Input (JSON):  {"policySet": {...}, "today": "YYYY-MM-DD"}
# Result:        {"valid": bool, "findings": [{severity, rule, message, path}]}
package authz

import rego.v1

import data.authz.lib

# --- input -----------------------------------------------------------------

policy_set := object.get(input, "policySet", null) if is_object(input)

policy_set_present if is_object(policy_set)

today := object.get(input, "today", null) if is_object(input)

# --- validation ------------------------------------------------------------

validate := result if {
	fs := sort([f | findings[f]])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
	}
}

# --- findings: input shape ---------------------------------------------------

findings contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with 'policySet' and 'today' fields",
		"path": "$",
	}
}

findings contains finding if {
	is_object(input)
	not lib.is_valid_date(today)
	finding := {
		"severity": "error",
		"rule": "input/today-invalid",
		"message": "today is missing or not a valid calendar date in YYYY-MM-DD format",
		"path": "$.today",
	}
}

findings contains finding if {
	is_object(input)
	not policy_set_present
	finding := {
		"severity": "error",
		"rule": "policyset/missing",
		"message": "policySet is missing or not an object",
		"path": "$.policySet",
	}
}

# --- findings: top-level fields ------------------------------------------------

findings contains finding if {
	policy_set_present
	not lib.is_nonempty_string(object.get(policy_set, "name", null))
	finding := {
		"severity": "error",
		"rule": "policyset/name-required",
		"message": "name is required: it must be a non-empty string",
		"path": "$.policySet.name",
	}
}

findings contains finding if {
	policy_set_present
	not is_number(object.get(policy_set, "currentVersion", null))
	finding := {
		"severity": "error",
		"rule": "policyset/current-version-missing",
		"message": "currentVersion is required: it must be an integer naming one of the declared versions",
		"path": "$.policySet.currentVersion",
	}
}

findings contains finding if {
	policy_set_present
	is_number(object.get(policy_set, "currentVersion", null))
	not is_integer(object.get(policy_set, "currentVersion", null))
	finding := {
		"severity": "error",
		"rule": "policyset/current-version-not-integer",
		"message": "currentVersion must be a whole number: version numbers are integers, not ranges",
		"path": "$.policySet.currentVersion",
	}
}

findings contains finding if {
	policy_set_present
	object.get(policy_set, "disabled", null) != null
	not is_boolean(object.get(policy_set, "disabled", null))
	finding := {
		"severity": "error",
		"rule": "policyset/disabled-not-boolean",
		"message": "disabled must be a boolean: true marks the whole set fail-closed",
		"path": "$.policySet.disabled",
	}
}

findings contains finding if {
	policy_set_present
	object.get(policy_set, "disabled", null) == true
	finding := {
		"severity": "warning",
		"rule": "policyset/disabled",
		"message": "the policy set is marked disabled: every request fails closed, and probe expectations are not self-checked while it is disabled",
		"path": "$.policySet.disabled",
	}
}

# --- findings: subject registry -------------------------------------------------

subjects := object.get(policy_set, "subjects", null) if policy_set_present

findings contains finding if {
	policy_set_present
	not is_array(subjects)
	finding := {
		"severity": "error",
		"rule": "policyset/subjects-must-be-array",
		"message": "subjects must be an array of {id, roles, flags} registry entries",
		"path": "$.policySet.subjects",
	}
}

findings contains finding if {
	policy_set_present
	is_array(subjects)
	some i, entry in subjects
	not is_object(entry)
	finding := {
		"severity": "error",
		"rule": "policyset/subject-must-be-object",
		"message": sprintf("registry entry %d must be an object with 'id', 'roles', and 'flags'", [i]),
		"path": sprintf("$.policySet.subjects[%d]", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(subjects)
	some i, entry in subjects
	is_object(entry)
	not lib.is_nonempty_string(object.get(entry, "id", null))
	finding := {
		"severity": "error",
		"rule": "policyset/subject-id-required",
		"message": sprintf("registry entry %d has no usable id: it must be a non-empty string", [i]),
		"path": sprintf("$.policySet.subjects[%d].id", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(subjects)
	some i, entry in subjects
	is_object(entry)
	some j, earlier in subjects
	j < i
	is_object(earlier)
	object.get(earlier, "id", null) == object.get(entry, "id", null)
	finding := {
		"severity": "error",
		"rule": "policyset/subject-id-duplicate",
		"message": sprintf("registry id '%s' appears more than once: a registry entry owns its id", [object.get(entry, "id", null)]),
		"path": sprintf("$.policySet.subjects[%d].id", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(subjects)
	some i, entry in subjects
	is_object(entry)
	object.get(entry, "roles", null) != null
	not is_array(object.get(entry, "roles", null))
	finding := {
		"severity": "error",
		"rule": "policyset/subject-roles-must-be-array",
		"message": sprintf("registry entry %d: roles must be an array of role names", [i]),
		"path": sprintf("$.policySet.subjects[%d].roles", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(subjects)
	some i, entry in subjects
	is_object(entry)
	is_array(object.get(entry, "roles", null))
	some j, role in object.get(entry, "roles", null)
	not lib.is_nonempty_string(role)
	finding := {
		"severity": "error",
		"rule": "policyset/subject-role-invalid",
		"message": sprintf("registry entry %d: role %d must be a non-empty string", [i, j]),
		"path": sprintf("$.policySet.subjects[%d].roles[%d]", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(subjects)
	some i, entry in subjects
	is_object(entry)
	object.get(entry, "flags", null) != null
	not is_array(object.get(entry, "flags", null))
	finding := {
		"severity": "error",
		"rule": "policyset/subject-flags-must-be-array",
		"message": sprintf("registry entry %d: flags must be an array of flag names", [i]),
		"path": sprintf("$.policySet.subjects[%d].flags", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(subjects)
	some i, entry in subjects
	is_object(entry)
	is_array(object.get(entry, "flags", null))
	some j, flag in object.get(entry, "flags", null)
	not lib.is_nonempty_string(flag)
	finding := {
		"severity": "error",
		"rule": "policyset/subject-flag-invalid",
		"message": sprintf("registry entry %d: flag %d must be a non-empty string", [i, j]),
		"path": sprintf("$.policySet.subjects[%d].flags[%d]", [i, j]),
	}
}

# --- findings: rule versions -----------------------------------------------------

versions := object.get(policy_set, "versions", null) if policy_set_present

findings contains finding if {
	policy_set_present
	not is_array(versions)
	finding := {
		"severity": "error",
		"rule": "policyset/versions-must-be-array",
		"message": "versions must be an array of rule versions",
		"path": "$.policySet.versions",
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	count(versions) == 0
	finding := {
		"severity": "error",
		"rule": "policyset/versions-required",
		"message": "versions must declare at least one version: an empty policy set has no current version to answer from",
		"path": "$.policySet.versions",
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	not is_object(v)
	finding := {
		"severity": "error",
		"rule": "policyset/version-must-be-object",
		"message": sprintf("version entry %d must be an object with 'version', 'effectiveFrom', and 'rules'", [i]),
		"path": sprintf("$.policySet.versions[%d]", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	not is_number(object.get(v, "version", null))
	finding := {
		"severity": "error",
		"rule": "policyset/version-number-missing",
		"message": sprintf("version entry %d has no usable number: version must be an integer", [i]),
		"path": sprintf("$.policySet.versions[%d].version", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_number(object.get(v, "version", null))
	not is_integer(object.get(v, "version", null))
	finding := {
		"severity": "error",
		"rule": "policyset/version-number-not-integer",
		"message": sprintf("version entry %d: version numbers are integers, not ranges", [i]),
		"path": sprintf("$.policySet.versions[%d].version", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	some j, earlier in versions
	j < i
	is_object(earlier)
	object.get(v, "version", null) == object.get(earlier, "version", null)
	finding := {
		"severity": "error",
		"rule": "policyset/version-number-duplicate",
		"message": sprintf("version %v is declared more than once: a version number names exactly one rule set", [object.get(v, "version", null)]),
		"path": sprintf("$.policySet.versions[%d].version", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	not lib.is_nonempty_string(object.get(v, "effectiveFrom", null))
	finding := {
		"severity": "error",
		"rule": "policyset/effective-from-required",
		"message": sprintf("version entry %d: effectiveFrom is required (YYYY-MM-DD)", [i]),
		"path": sprintf("$.policySet.versions[%d].effectiveFrom", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	lib.is_nonempty_string(object.get(v, "effectiveFrom", null))
	not lib.is_valid_date(object.get(v, "effectiveFrom", null))
	finding := {
		"severity": "error",
		"rule": "policyset/effective-from-invalid",
		"message": sprintf("version entry %d: effectiveFrom must be a valid calendar date in YYYY-MM-DD format", [i]),
		"path": sprintf("$.policySet.versions[%d].effectiveFrom", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	has_effective_to(v)
	not lib.is_valid_date(object.get(v, "effectiveTo", null))
	finding := {
		"severity": "error",
		"rule": "policyset/effective-to-invalid",
		"message": sprintf("version entry %d: effectiveTo must be a valid calendar date in YYYY-MM-DD format", [i]),
		"path": sprintf("$.policySet.versions[%d].effectiveTo", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	lib.is_valid_date(object.get(v, "effectiveFrom", null))
	lib.is_valid_date(object.get(v, "effectiveTo", null))
	version_from_days(v) > version_to_days(v)
	finding := {
		"severity": "error",
		"rule": "policyset/effective-to-before-from",
		"message": sprintf("version entry %d: effectiveTo lies before effectiveFrom", [i]),
		"path": sprintf("$.policySet.versions[%d].effectiveTo", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	not is_array(object.get(v, "rules", null))
	finding := {
		"severity": "error",
		"rule": "policyset/rules-must-be-array",
		"message": sprintf("version entry %d: rules must be an array (an empty version denies everything in it — declare it, do not omit it)", [i]),
		"path": sprintf("$.policySet.versions[%d].rules", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	count(object.get(v, "rules", [])) == 0
	finding := {
		"severity": "warning",
		"rule": "policyset/version-has-no-rules",
		"message": sprintf("version entry %d declares no rules: every request during this version fails closed — confirm that is intended", [i]),
		"path": sprintf("$.policySet.versions[%d].rules", [i]),
	}
}

# Two versions must never be effective on the same date: which rule set
# answers a request would depend on iteration order, not on the document.
findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, a in versions
	some j, b in versions
	j > i
	versions_effective_usable(a)
	versions_effective_usable(b)
	version_from_days(a) <= version_to_days(b)
	version_from_days(b) <= version_to_days(a)
	finding := {
		"severity": "error",
		"rule": "policyset/version-overlap",
		"message": sprintf("version %v and version %v are both effective on some shared date: two versions must never overlap", [object.get(a, "version", null), object.get(b, "version", null)]),
		"path": sprintf("$.policySet.versions[%d]", [j]),
	}
}

versions_effective_usable(v) if {
	is_object(v)
	lib.is_valid_date(object.get(v, "effectiveFrom", null))
	not has_effective_to(v)
}

versions_effective_usable(v) if {
	is_object(v)
	lib.is_valid_date(object.get(v, "effectiveFrom", null))
	lib.is_valid_date(object.get(v, "effectiveTo", null))
	version_from_days(v) <= version_to_days(v)
}

# --- findings: the current version ----------------------------------------------

findings contains finding if {
	policy_set_present
	is_array(versions)
	is_number(object.get(policy_set, "currentVersion", null))
	not has_active_version(policy_set)
	finding := {
		"severity": "error",
		"rule": "policyset/current-version-unknown",
		"message": sprintf("currentVersion %v does not name any declared version", [object.get(policy_set, "currentVersion", null)]),
		"path": "$.policySet.currentVersion",
	}
}

current_version := active_version(policy_set)

findings contains finding if {
	policy_set_present
	is_object(current_version)
	lib.is_valid_date(today)
	lib.is_valid_date(object.get(current_version, "effectiveFrom", null))
	version_from_days(current_version) > lib.date_to_days(today)
	finding := {
		"severity": "error",
		"rule": "policyset/current-version-not-yet-effective",
		"message": sprintf("the current version does not take effect until %s: today it answers nothing", [object.get(current_version, "effectiveFrom", null)]),
		"path": "$.policySet.currentVersion",
	}
}

findings contains finding if {
	policy_set_present
	is_object(current_version)
	lib.is_valid_date(today)
	lib.is_valid_date(object.get(current_version, "effectiveFrom", null))
	lib.date_to_days(today) - version_from_days(current_version) > 365
	finding := {
		"severity": "warning",
		"rule": "policyset/current-version-stale",
		"message": "the current version took effect more than 365 days ago: this policy set has not been re-versioned in over a year",
		"path": "$.policySet.currentVersion",
	}
}

# --- findings: rules ---------------------------------------------------------------

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	not is_object(r)
	finding := {
		"severity": "error",
		"rule": "policyset/rule-must-be-object",
		"message": sprintf("version %v rule %d must be an object with 'id', 'effect', 'subject', 'action', and 'resource'", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d]", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	not lib.is_nonempty_string(object.get(r, "id", null))
	finding := {
		"severity": "error",
		"rule": "policyset/rule-id-required",
		"message": sprintf("version %v rule %d has no usable id: the rule that fired in an audit trace must have a name", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].id", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	some k, earlier in object.get(v, "rules", [])
	k < j
	is_object(earlier)
	object.get(r, "id", null) == object.get(earlier, "id", null)
	finding := {
		"severity": "error",
		"rule": "policyset/rule-id-duplicate",
		"message": sprintf("version %v: rule id '%s' appears more than once within the same version", [object.get(v, "version", null), object.get(r, "id", null)]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].id", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	not object.get(r, "effect", null) in {"allow", "deny"}
	finding := {
		"severity": "error",
		"rule": "policyset/rule-effect-invalid",
		"message": sprintf("version %v rule %d: effect must be 'allow' or 'deny'", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].effect", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	not is_object(object.get(r, "subject", null))
	finding := {
		"severity": "error",
		"rule": "policyset/rule-subject-required",
		"message": sprintf("version %v rule %d: subject is required — an object with exactly one of 'id', 'role', or 'flag'", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].subject", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	is_object(object.get(r, "subject", null))
	count(present_selectors(object.get(r, "subject", null))) > 1
	finding := {
		"severity": "error",
		"rule": "policyset/rule-subject-ambiguous",
		"message": sprintf("version %v rule %d: subject names more than one of id/role/flag — a rule states one subject selector, not a disjunction", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].subject", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	is_object(object.get(r, "subject", null))
	count(present_selectors(object.get(r, "subject", null))) == 0
	finding := {
		"severity": "error",
		"rule": "policyset/rule-subject-required",
		"message": sprintf("version %v rule %d: subject must name exactly one of 'id', 'role', or 'flag' with a non-empty string", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].subject", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	not lib.is_nonempty_string(object.get(r, "action", null))
	finding := {
		"severity": "error",
		"rule": "policyset/rule-action-required",
		"message": sprintf("version %v rule %d: action is required (an exact string or a trailing-* pattern)", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].action", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	lib.is_nonempty_string(object.get(r, "action", null))
	not is_pattern(object.get(r, "action", null))
	finding := {
		"severity": "error",
		"rule": "policyset/rule-action-wildcard-invalid",
		"message": sprintf("version %v rule %d: action patterns are an exact string or end in a single '*': %q is neither", [object.get(v, "version", null), j, object.get(r, "action", null)]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].action", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	not lib.is_nonempty_string(object.get(r, "resource", null))
	finding := {
		"severity": "error",
		"rule": "policyset/rule-resource-required",
		"message": sprintf("version %v rule %d: resource is required (an exact string or a trailing-* pattern)", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].resource", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	lib.is_nonempty_string(object.get(r, "resource", null))
	not is_pattern(object.get(r, "resource", null))
	finding := {
		"severity": "error",
		"rule": "policyset/rule-resource-wildcard-invalid",
		"message": sprintf("version %v rule %d: resource patterns are an exact string or end in a single '*': %q is neither", [object.get(v, "version", null), j, object.get(r, "resource", null)]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].resource", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	object.get(r, "condition", null) != null
	not is_object(object.get(r, "condition", null))
	finding := {
		"severity": "error",
		"rule": "policyset/rule-condition-must-be-object",
		"message": sprintf("version %v rule %d: condition must be an object mapping context fields to expected values", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].condition", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	is_object(object.get(r, "condition", null))
	some field, expected in object.get(r, "condition", null)
	not lib.is_nonempty_string(field)
	finding := {
		"severity": "error",
		"rule": "policyset/rule-condition-key-invalid",
		"message": sprintf("version %v rule %d: condition keys must be non-empty strings", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].condition", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	is_object(object.get(r, "condition", null))
	some field, expected in object.get(r, "condition", null)
	not condition_value_scalar(expected)
	finding := {
		"severity": "error",
		"rule": "policyset/rule-condition-value-invalid",
		"message": sprintf("version %v rule %d: condition value for '%s' must be a string, number, or boolean — conditions are equality checks, not expressions", [object.get(v, "version", null), j, field]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].condition", [i, j]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(versions)
	some i, v in versions
	is_object(v)
	is_array(object.get(v, "rules", null))
	some j, r in object.get(v, "rules", [])
	is_object(r)
	object.get(r, "description", null) != null
	not lib.is_nonempty_string(object.get(r, "description", null))
	finding := {
		"severity": "error",
		"rule": "policyset/rule-description-invalid",
		"message": sprintf("version %v rule %d: description, when present, must be a non-empty string", [object.get(v, "version", null), j]),
		"path": sprintf("$.policySet.versions[%d].rules[%d].description", [i, j]),
	}
}

condition_value_scalar(v) if is_string(v)

condition_value_scalar(v) if is_number(v)

condition_value_scalar(v) if is_boolean(v)

# --- findings: probes -------------------------------------------------------------

probes := object.get(policy_set, "probes", null) if policy_set_present

findings contains finding if {
	policy_set_present
	not is_array(probes)
	finding := {
		"severity": "error",
		"rule": "policyset/probes-must-be-array",
		"message": "probes must be an array of {id, subject, action, resource, context?, expect} entries",
		"path": "$.policySet.probes",
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	count(probes) == 0
	finding := {
		"severity": "warning",
		"rule": "policyset/probes-empty",
		"message": "the policy set declares no probes: the disabled-state test inventory will be empty",
		"path": "$.policySet.probes",
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	some i, p in probes
	not is_object(p)
	finding := {
		"severity": "error",
		"rule": "policyset/probe-must-be-object",
		"message": sprintf("probe entry %d must be an object with 'id', 'subject', 'action', 'resource', and 'expect'", [i]),
		"path": sprintf("$.policySet.probes[%d]", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	some i, p in probes
	is_object(p)
	not lib.is_nonempty_string(object.get(p, "id", null))
	finding := {
		"severity": "error",
		"rule": "policyset/probe-id-required",
		"message": sprintf("probe entry %d has no usable id", [i]),
		"path": sprintf("$.policySet.probes[%d].id", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	some i, p in probes
	is_object(p)
	some k, earlier in probes
	k < i
	is_object(earlier)
	object.get(p, "id", null) == object.get(earlier, "id", null)
	finding := {
		"severity": "error",
		"rule": "policyset/probe-id-duplicate",
		"message": sprintf("probe id '%s' appears more than once", [object.get(p, "id", null)]),
		"path": sprintf("$.policySet.probes[%d].id", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	some i, p in probes
	is_object(p)
	not lib.is_nonempty_string(object.get(p, "subject", null))
	finding := {
		"severity": "error",
		"rule": "policyset/probe-subject-required",
		"message": sprintf("probe entry %d: subject is required — the id of a registered subject", [i]),
		"path": sprintf("$.policySet.probes[%d].subject", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	some i, p in probes
	is_object(p)
	lib.is_nonempty_string(object.get(p, "subject", null))
	not object.get(p, "subject", null) in registry_ids(policy_set)
	finding := {
		"severity": "error",
		"rule": "policyset/probe-subject-unknown",
		"message": sprintf("probe entry %d: subject '%s' is not in the registry — a probe replays a request some subject really made", [i, object.get(p, "subject", null)]),
		"path": sprintf("$.policySet.probes[%d].subject", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	some i, p in probes
	is_object(p)
	not lib.is_nonempty_string(object.get(p, "action", null))
	finding := {
		"severity": "error",
		"rule": "policyset/probe-action-required",
		"message": sprintf("probe entry %d: action is required", [i]),
		"path": sprintf("$.policySet.probes[%d].action", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	some i, p in probes
	is_object(p)
	not lib.is_nonempty_string(object.get(p, "resource", null))
	finding := {
		"severity": "error",
		"rule": "policyset/probe-resource-required",
		"message": sprintf("probe entry %d: resource is required", [i]),
		"path": sprintf("$.policySet.probes[%d].resource", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	some i, p in probes
	is_object(p)
	object.get(p, "context", null) != null
	not is_object(object.get(p, "context", null))
	finding := {
		"severity": "error",
		"rule": "policyset/probe-context-must-be-object",
		"message": sprintf("probe entry %d: context, when present, must be an object", [i]),
		"path": sprintf("$.policySet.probes[%d].context", [i]),
	}
}

findings contains finding if {
	policy_set_present
	is_array(probes)
	some i, p in probes
	is_object(p)
	not object.get(p, "expect", null) in {"allow", "deny"}
	finding := {
		"severity": "error",
		"rule": "policyset/probe-expect-invalid",
		"message": sprintf("probe entry %d: expect must be 'allow' or 'deny'", [i]),
		"path": sprintf("$.policySet.probes[%d].expect", [i]),
	}
}

# --- findings: probes replayed against the set itself ------------------------------

# A probe is a promise about the current version. This replays every
# usable probe through the decision engine and flags any expectation the
# set does not keep — the set is self-testing in CI, before it ever
# answers a real request.
findings contains finding if {
	policy_set_present
	is_array(probes)
	not ps_disabled(policy_set)
	has_active_version(policy_set)
	some i, p in probes
	probe_well_formed(p)
	outcome := decide_request(probe_request(p), policy_set)
	outcome.decision != object.get(p, "expect", null)
	finding := {
		"severity": "error",
		"rule": "policyset/probe-expectation-mismatch",
		"message": sprintf("probe '%s' expects %s but the current policy set answers %s (rule %s)", [
			object.get(p, "id", null),
			object.get(p, "expect", null),
			outcome.decision,
			outcome.rule,
		]),
		"path": sprintf("$.policySet.probes[%d].expect", [i]),
	}
}

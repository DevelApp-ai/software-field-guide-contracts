# The broker grant document validated alone — The Software Field
# Guide, issue #104.
#
# Every finding below judges ONE document: the broker's word — the
# consumer identities it declares, and every grant it issued, each
# naming one declared principal, one component pinned by sha256
# digest, the allowed action set, and an expiry. The joins live in
# the gate: a grant for a component the package manifest never named
# is a claim nobody can check; a grant pinning a digest the manifest
# never published is a grant for other bytes — those are judged where
# the grants meet the manifest.
package broker

import rego.v1

import data.broker.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_input_findings := f_input_invalid | f_today_invalid

validate_doc_findings := f_broker_missing | f_broker_stamps

validate_principals_findings := (f_principals_array | f_principals_content) | f_principals_duplicates

validate_rows_findings := f_grants_array | f_grants_content

validate_grant_identity_findings := ((f_grant_principal_required | f_grant_principal_undeclared) | f_grant_component_required) | f_grant_duplicate

validate_grant_digest_findings := f_grant_digest_required | f_grant_digest_malformed

validate_grant_actions_findings := ((((f_grant_actions_array | f_grant_actions_required) | f_grant_action_content) | f_grant_action_wildcard) | f_grant_action_glob) | f_grant_action_duplicate

validate_grant_clock_findings := (f_grant_expires_required | f_grant_expires_invalid) | f_grant_expires_in_past

validate_findings := ((((validate_input_findings | validate_doc_findings) | validate_principals_findings) | validate_rows_findings) | validate_grant_identity_findings) | (validate_grant_digest_findings | (validate_grant_actions_findings | validate_grant_clock_findings))

# --- findings: the input and the clock ------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the broker grant document as input.broker",
		"path": "$",
	}
}

f_today_invalid contains finding if {
	is_object(input)
	not lib.is_valid_date(object.get(input, "today", null))
	finding := {
		"severity": "error",
		"rule": "input/today-invalid",
		"message": "today must be a real YYYY-MM-DD date — the clock is injected, never read",
		"path": "$.today",
	}
}

# --- findings: the broker grant document -----------------------------------------

f_broker_missing contains finding if {
	is_object(input)
	not is_object(broker_doc)
	finding := {
		"severity": "error",
		"rule": "broker/missing",
		"message": "the broker grant document is required: pass it as input.broker — the declared principals and the grants the broker issued",
		"path": "$.broker",
	}
}

# The broker grant document is an owned, versioned artifact: a grant
# set nobody re-reads is a grant set nobody still vouches for.
f_broker_stamps contains finding if {
	is_object(broker_doc)
	not is_positive_integer(object.get(broker_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "broker/version-required",
		"message": sprintf("the broker grant document must carry a version (a positive integer): the grants are versioned like the components they consume (%s)", [broker_file]),
		"path": "$.broker.version",
	}
}

f_broker_stamps contains finding if {
	is_object(broker_doc)
	not lib.is_valid_date(object.get(broker_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "broker/reviewed-on-invalid",
		"message": sprintf("the broker grant document must carry reviewedOn as a real YYYY-MM-DD date (%s)", [broker_file]),
		"path": "$.broker.reviewedOn",
	}
}

f_broker_stamps contains finding if {
	is_object(broker_doc)
	lib.is_valid_date(object.get(broker_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(broker_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "broker/reviewed-in-future",
		"message": sprintf("the broker grant document carries a reviewedOn date in the future (%s)", [broker_file]),
		"path": "$.broker.reviewedOn",
	}
}

f_broker_stamps contains finding if {
	is_object(broker_doc)
	lib.is_valid_date(object.get(broker_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(broker_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "broker/reviewed-stale",
		"message": sprintf("the broker grant document was reviewed more than 365 days before today: grants nobody re-reads are grants nobody still vouches for (%s)", [broker_file]),
		"path": "$.broker.reviewedOn",
	}
}

f_broker_stamps contains finding if {
	is_object(broker_doc)
	not lib.is_nonempty_string(object.get(broker_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "broker/owner-required",
		"message": sprintf("the broker grant document must name an owner: grants without an owner are scope nobody maintains (%s)", [broker_file]),
		"path": "$.broker.owner",
	}
}

# --- findings: the declared consumer identities -----------------------------------

f_principals_array contains finding if {
	is_object(broker_doc)
	not is_array(object.get(broker_doc, "principals", null))
	finding := {
		"severity": "error",
		"rule": "principals/must-be-array",
		"message": sprintf("principals must be an array of the consumer identities the broker declares (%s)", [broker_file]),
		"path": "$.broker.principals",
	}
}

f_principals_content contains finding if {
	some i, p in principal_entries
	not lib.is_nonempty_string(p)
	finding := {
		"severity": "error",
		"rule": "principals/name-required",
		"message": sprintf("principal entry %d must carry a non-empty name: an unnamed identity cannot be cited in a finding (%s)", [i, broker_file]),
		"path": sprintf("$.broker.principals[%d]", [i]),
	}
}

f_principals_duplicates contains finding if {
	some p in declared_principals
	count([x | some x in principal_entries; x == p]) > 1
	finding := {
		"severity": "error",
		"rule": "principal/name-duplicate",
		"message": sprintf("consumer identity '%s' is declared more than once: an identity declared twice is a grant set the gate cannot count (%s)", [p, broker_file]),
		"path": "$.broker.principals",
	}
}

# --- findings: the grant rows ------------------------------------------------------

f_grants_array contains finding if {
	is_object(broker_doc)
	not is_array(object.get(broker_doc, "grants", null))
	finding := {
		"severity": "error",
		"rule": "grants/must-be-array",
		"message": sprintf("the grants must be an array of {principal, component, digest, actions, expires} rows (%s)", [broker_file]),
		"path": "$.broker.grants",
	}
}

f_grants_array contains finding if {
	is_object(broker_doc)
	is_array(object.get(broker_doc, "grants", null))
	count(grant_rows) == 0
	finding := {
		"severity": "error",
		"rule": "grants/rows-required",
		"message": sprintf("the broker grant document must carry at least one grant: a broker that grants nothing brokers nothing (%s)", [broker_file]),
		"path": "$.broker.grants",
	}
}

f_grants_content contains finding if {
	some i, g in as_array(broker_doc, "grants")
	not is_object(g)
	finding := {
		"severity": "error",
		"rule": "grants/row-must-be-object",
		"message": sprintf("grant row %d must be an object with principal, component, digest, actions, and expires (%s)", [i, broker_file]),
		"path": sprintf("$.broker.grants[%d]", [i]),
	}
}

# --- findings: each grant's named identity ----------------------------------------

f_grant_principal_required contains finding if {
	some i, g in grant_rows
	not lib.is_nonempty_string(grant_principal(g))
	finding := {
		"severity": "error",
		"rule": "grant/principal-required",
		"message": sprintf("grant row %d must name one principal: a grant without a consumer identity is a grant nobody answers for (%s)", [i, broker_file]),
		"path": sprintf("$.broker.grants[%d].principal", [i]),
	}
}

# The named principal must be one the broker declared: the broker
# vouches for the identities it grants, not for names that merely
# appear in grants.
f_grant_principal_undeclared contains finding if {
	some i, g in grant_rows
	lib.is_nonempty_string(grant_principal(g))
	not principal_declared(grant_principal(g))
	finding := {
		"severity": "error",
		"rule": "grant/principal-undeclared",
		"message": sprintf("grant row %d names the principal '%s', which the broker never declared: a grant for an undeclared consumer identity is a grant nobody answers for (%s)", [i, grant_principal(g), broker_file]),
		"path": sprintf("$.broker.grants[%d].principal", [i]),
	}
}

# --- findings: each grant's single component ---------------------------------------

f_grant_component_required contains finding if {
	some i, g in grant_rows
	not lib.is_nonempty_string(grant_component(g))
	finding := {
		"severity": "error",
		"rule": "grant/component-required",
		"message": sprintf("grant row %d must name one component: a grant naming no component consumes nothing in particular, and a grant naming many is two grants (%s)", [i, broker_file]),
		"path": sprintf("$.broker.grants[%d].component", [i]),
	}
}

# --- findings: each grant's pinned digest -------------------------------------------

f_grant_digest_required contains finding if {
	some i, g in grant_rows
	not lib.is_nonempty_string(grant_digest(g))
	finding := {
		"severity": "error",
		"rule": "grant/digest-required",
		"message": sprintf("grant row %d must pin a digest: a grant for a component by name alone is a grant that can change under the broker (%s)", [i, broker_file]),
		"path": sprintf("$.broker.grants[%d].digest", [i]),
	}
}

f_grant_digest_malformed contains finding if {
	some i, g in grant_rows
	lib.is_nonempty_string(grant_digest(g))
	not is_artifact_digest(grant_digest(g))
	finding := {
		"severity": "error",
		"rule": "grant/digest-malformed",
		"message": sprintf("the grant's pinned digest must be a sha256 digest (64 lowercase hex characters) — '%v' is not a digest the gate agreed to read (%s)", [grant_digest(g), broker_file]),
		"path": sprintf("$.broker.grants[%d].digest", [i]),
	}
}

# --- findings: each grant's allowed action set --------------------------------------

f_grant_actions_array contains finding if {
	some i, g in grant_rows
	not is_array(object.get(g, "actions", null))
	finding := {
		"severity": "error",
		"rule": "grant/actions-must-be-array",
		"message": sprintf("grant row %d must carry its allowed action set as an array of exact action names (%s)", [i, broker_file]),
		"path": sprintf("$.broker.grants[%d].actions", [i]),
	}
}

# A grant with no allowed actions is a grant granting nothing — at
# estate scale that is usually a row somebody forgot to finish.
f_grant_actions_required contains finding if {
	some i, g in grant_rows
	grant_actions_readable(g)
	count(grant_action_rows(g)) == 0
	finding := {
		"severity": "error",
		"rule": "grant/actions-required",
		"message": sprintf("grant row %d must name at least one allowed action: a grant with an empty action set grants nothing (%s)", [i, broker_file]),
		"path": sprintf("$.broker.grants[%d].actions", [i]),
	}
}

f_grant_action_content contains finding if {
	some i, g in grant_rows
	some a in as_array(g, "actions")
	not lib.is_nonempty_string(a)
	finding := {
		"severity": "error",
		"rule": "grant/action-name-required",
		"message": sprintf("grant row %d carries an action that is not a non-empty name: an unnamed action cannot be allowed (%s)", [i, broker_file]),
		"path": sprintf("$.broker.grants[%d].actions", [i]),
	}
}

# Minimality, first reading: a wildcard grant can do anything —
# exactly what the broker exists to prevent.
f_grant_action_wildcard contains finding if {
	some i, g in grant_rows
	grant_actions_readable(g)
	grant_action_wildcard(g)
	exact := grant_action_wildcards(g)
	finding := {
		"severity": "error",
		"rule": "grant/action-wildcard",
		"message": sprintf("grant row %d allows the wildcard action (%s), which matches everything: a grant that can do anything is the scope the broker exists to prevent (%s)", [i, exact, broker_file]),
		"path": sprintf("$.broker.grants[%d].actions", [i]),
	}
}

# Minimality, second reading: a metacharacter action is a wildcard
# wearing a beard — the gate models the glob metacharacters and
# refuses on either reading of "broad".
f_grant_action_glob contains finding if {
	some i, g in grant_rows
	grant_actions_readable(g)
	grant_action_glob(g)
	exact := grant_action_globs(g)
	finding := {
		"severity": "error",
		"rule": "grant/action-glob",
		"message": sprintf("grant row %d allows the action '%s', which carries glob metacharacters the gate refuses to guess against: the allowed action set is exact names or it is not a set (%s)", [i, exact, broker_file]),
		"path": sprintf("$.broker.grants[%d].actions", [i]),
	}
}

f_grant_action_duplicate contains finding if {
	some i, g in grant_rows
	grant_actions_readable(g)
	grant_action_duplicate(g)
	exact := grant_duplicate_actions(g)
	finding := {
		"severity": "error",
		"rule": "grant/action-duplicate",
		"message": sprintf("grant row %d lists the action '%s' more than once: an action set is a set (%s)", [i, exact, broker_file]),
		"path": sprintf("$.broker.grants[%d].actions", [i]),
	}
}

# --- findings: each grant's expiry ---------------------------------------------------

# Every grant carries an expiry because scope without a clock is
# scope forever.
f_grant_expires_required contains finding if {
	some i, g in grant_rows
	not lib.is_nonempty_string(grant_expires(g))
	finding := {
		"severity": "error",
		"rule": "grant/expires-required",
		"message": sprintf("grant row %d must carry an expiry: a grant without a clock is scope granted forever (%s)", [i, broker_file]),
		"path": sprintf("$.broker.grants[%d].expires", [i]),
	}
}

f_grant_expires_invalid contains finding if {
	some i, g in grant_rows
	lib.is_nonempty_string(grant_expires(g))
	not lib.is_valid_date(grant_expires(g))
	finding := {
		"severity": "error",
		"rule": "grant/expires-invalid",
		"message": sprintf("grant row %d carries an expiry that is not a real YYYY-MM-DD date (%s)", [i, broker_file]),
		"path": sprintf("$.broker.grants[%d].expires", [i]),
	}
}

# An expired grant is a grant the broker never revoked: the document
# still says it, and the document is wrong.
f_grant_expires_in_past contains finding if {
	some i, g in grant_rows
	grant_expired(g)
	finding := {
		"severity": "error",
		"rule": "grant/expires-in-past",
		"message": sprintf("grant row %d expired on %s, before today: an expired grant still on the books is a grant the broker never revoked (%s)", [i, grant_expires(g), broker_file]),
		"path": sprintf("$.broker.grants[%d].expires", [i]),
	}
}

# --- findings: the same grant twice ---------------------------------------------------

# One principal, one component, one grant: a principal granted the
# same component twice is a grant nobody can diff.
f_grant_duplicate contains finding if {
	some i, g in grant_rows
	grant_row_readable(g)
	count([h |
		some h in grant_rows
		grant_row_readable(h)
		grant_principal(h) == grant_principal(g)
		grant_component(h) == grant_component(g)
	]) > 1
	finding := {
		"severity": "error",
		"rule": "grant/duplicate",
		"message": sprintf("the grant of '%s' on '%s' appears more than once: one principal, one component, one grant — anything else is a grant nobody can diff (%s)", [grant_principal(g), grant_component(g), broker_file]),
		"path": sprintf("$.broker.grants[%d]", [i]),
	}
}

# --- the exact offenders, cited deterministically -------------------------------------

grant_action_wildcards(g) := a if {
	exact := [x | some x in grant_action_rows(g); x == "*"]
	count(exact) > 0
	a := exact[0]
}

grant_action_globs(g) := a if {
	exact := [x | some x in grant_action_rows(g); not x == "*"; regex.match(`[*?[{]`, x)]
	count(exact) > 0
	a := exact[0]
}

grant_duplicate_actions(g) := a if {
	exact := [x | some x in grant_action_rows(g); count([y | some y in grant_action_rows(g); y == x]) > 1]
	count(exact) > 0
	a := exact[0]
}

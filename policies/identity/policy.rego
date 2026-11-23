# The identity manifest validated alone — The Software Field Guide,
# issue #108.
#
# Every finding below judges ONE document: the identity manifest,
# the platform's word for who its apps are and which secrets they
# may reference. The identity-and-secrets chapter's questions must
# all have answers — which identity declares this reference, which
# secret it points at, under which scope, since when — and the
# answers must be checkable: scope minimality is judged here on the
# manifest's own words (no wildcard scopes, no glob shapes the
# platform never granted), while the joins live in the gate — a
# secret the catalog never declared, an identity the catalog never
# admitted, a scope the catalog never wrote, and a rotation clock
# that ran out are all judged where the manifest meets the catalog.
package identity

import rego.v1

import data.identity.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_findings := (((((((((f_input_invalid | f_today_invalid) | f_manifest_missing) | f_manifest_stamps) | f_identities_shape) | f_identity_content) | f_identity_duplicate) | f_references_shape) | f_reference_content) | f_reference_scope) | f_reference_since

# --- findings: the input and the clock -----------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the identity manifest as input.manifest",
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

# --- findings: the manifest document and its house stamps -------------------------

f_manifest_missing contains finding if {
	not is_object(manifest_doc)
	finding := {
		"severity": "error",
		"rule": "manifest/missing",
		"message": "the identity manifest is required: pass it as input.manifest",
		"path": "$.manifest",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	not is_positive_integer(manifest_version)
	finding := {
		"severity": "error",
		"rule": "manifest/version-required",
		"message": sprintf("the identity manifest must carry a version (a positive integer): an unversioned manifest is a declaration nobody can pin a change against (%s)", [manifest_file]),
		"path": "$.manifest.version",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	not lib.is_valid_date(manifest_reviewed_on)
	finding := {
		"severity": "error",
		"rule": "manifest/reviewed-on-invalid",
		"message": sprintf("the identity manifest must carry reviewedOn as a real YYYY-MM-DD date (%s)", [manifest_file]),
		"path": "$.manifest.reviewedOn",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	lib.is_valid_date(manifest_reviewed_on)
	lib.is_valid_date(today_date)
	lib.date_to_days(manifest_reviewed_on) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "manifest/reviewed-in-future",
		"message": sprintf("the identity manifest carries a reviewedOn date in the future (%s)", [manifest_file]),
		"path": "$.manifest.reviewedOn",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	lib.is_valid_date(manifest_reviewed_on)
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(manifest_reviewed_on) > 365
	finding := {
		"severity": "error",
		"rule": "manifest/reviewed-stale",
		"message": sprintf("the identity manifest was reviewed more than 365 days before today: the platform's identities changed since, and this document says nothing about it (%s)", [manifest_file]),
		"path": "$.manifest.reviewedOn",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	not lib.is_nonempty_string(manifest_owner)
	finding := {
		"severity": "error",
		"rule": "manifest/owner-required",
		"message": sprintf("the identity manifest must name an owner: a declaration of identity with an owner and a review cadence is the discipline (%s)", [manifest_file]),
		"path": "$.manifest.owner",
	}
}

# --- findings: the identities the manifest declares -------------------------------

f_identities_shape contains finding if {
	is_object(manifest_doc)
	not is_array(object.get(manifest_doc, "identities", null))
	finding := {
		"severity": "error",
		"rule": "identities/must-be-array",
		"message": sprintf("the identity manifest's identities must be an array of {name, references} rows (%s)", [manifest_file]),
		"path": "$.manifest.identities",
	}
}

f_identities_shape contains finding if {
	is_object(manifest_doc)
	is_array(object.get(manifest_doc, "identities", null))
	count(object.get(manifest_doc, "identities", [])) == 0
	finding := {
		"severity": "error",
		"rule": "identities/required",
		"message": sprintf("the identity manifest must declare at least one identity: an identity nobody declared is a workload running on trust alone (%s)", [manifest_file]),
		"path": "$.manifest.identities",
	}
}

f_identities_shape contains finding if {
	is_object(manifest_doc)
	is_array(object.get(manifest_doc, "identities", null))
	some i in object.get(manifest_doc, "identities", [])
	not is_object(i)
	finding := {
		"severity": "error",
		"rule": "identities/row-must-be-object",
		"message": sprintf("every identity row must be an object: {name, references} (%s)", [manifest_file]),
		"path": "$.manifest.identities",
	}
}

f_identity_content contains finding if {
	some i in identity_rows
	not lib.is_nonempty_string(identity_name(i))
	finding := {
		"severity": "error",
		"rule": "identity/name-required",
		"message": sprintf("every identity row must name the app it declares: an unnamed identity is nobody to hold the secrets it references (%s)", [manifest_file]),
		"path": "$.manifest.identities",
	}
}

f_identity_duplicate contains finding if {
	some i in identity_rows
	lib.is_nonempty_string(identity_name(i))
	count([x | some x in identity_rows; identity_name(x) == identity_name(i)]) > 1
	finding := {
		"severity": "error",
		"rule": "identity/name-duplicate",
		"message": sprintf("the identity '%v' is declared more than once: one app, one identity row (%s)", [identity_name(i), manifest_file]),
		"path": "$.manifest.identities",
	}
}

# --- findings: the references each identity declares -------------------------------

f_references_shape contains finding if {
	some i in identity_rows
	not is_array(object.get(i, "references", null))
	finding := {
		"severity": "error",
		"rule": "references/must-be-array",
		"message": sprintf("every identity's references must be an array of {secret, scope, since} rows (%s)", [manifest_file]),
		"path": "$.manifest.identities",
	}
}

f_references_shape contains finding if {
	some i in identity_rows
	is_array(object.get(i, "references", null))
	some r in object.get(i, "references", [])
	not is_object(r)
	finding := {
		"severity": "error",
		"rule": "references/row-must-be-object",
		"message": sprintf("every reference row must be an object: {secret, scope, since} (%s)", [manifest_file]),
		"path": "$.manifest.identities",
	}
}

f_reference_content contains finding if {
	some p in reference_pairs
	not lib.is_nonempty_string(reference_secret(p.row))
	finding := {
		"severity": "error",
		"rule": "reference/secret-required",
		"message": sprintf("every reference must name the secret it points at: a reference to nowhere is trust in nothing (%s)", [manifest_file]),
		"path": "$.manifest.identities",
	}
}

f_reference_content contains finding if {
	some p in reference_pairs
	not lib.is_nonempty_string(reference_scope(p.row))
	finding := {
		"severity": "error",
		"rule": "reference/scope-required",
		"message": sprintf("every reference must carry the scope it exercises: a reference without a scope is a grant the platform never narrowed (%s)", [manifest_file]),
		"path": "$.manifest.identities",
	}
}

# --- findings: scope minimality, judged on the manifest's own words ----------------

f_reference_scope contains finding if {
	some p in reference_pairs
	reference_scope(p.row) == "*"
	finding := {
		"severity": "error",
		"rule": "reference/scope-wildcard",
		"message": sprintf("the identity '%v' references the secret '%v' with the wildcard scope '*': a scope that means everything means the platform granted nothing it can name (%s)", [p.identity, reference_secret(p.row), manifest_file]),
		"path": "$.manifest.identities",
	}
}

f_reference_scope contains finding if {
	some p in reference_pairs
	reference_scope(p.row) != "*"
	count([c | some c in ["*", "?", "["]; contains(reference_scope(p.row), c)]) > 0
	finding := {
		"severity": "error",
		"rule": "reference/scope-glob",
		"message": sprintf("the identity '%v' references the secret '%v' with the glob-shaped scope '%v': the platform grants scopes it can name, not patterns it must interpret (%s)", [p.identity, reference_secret(p.row), reference_scope(p.row), manifest_file]),
		"path": "$.manifest.identities",
	}
}

# --- findings: since when the reference existed -----------------------------------

f_reference_since contains finding if {
	some p in reference_pairs
	not lib.is_valid_date(reference_since(p.row))
	finding := {
		"severity": "error",
		"rule": "reference/since-invalid",
		"message": sprintf("every reference must carry its since day as a real YYYY-MM-DD date: an entitlement without a birthday is an entitlement nobody can audit (%s)", [manifest_file]),
		"path": "$.manifest.identities",
	}
}

f_reference_since contains finding if {
	some p in reference_pairs
	lib.is_valid_date(reference_since(p.row))
	lib.is_valid_date(today_date)
	lib.date_to_days(reference_since(p.row)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "reference/since-in-future",
		"message": sprintf("the reference to '%v' on the identity '%v' carries a since date in the future: an entitlement that starts tomorrow is not held today (%s)", [reference_secret(p.row), p.identity, manifest_file]),
		"path": "$.manifest.identities",
	}
}

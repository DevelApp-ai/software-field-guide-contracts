# The policy component catalog validated alone — The Software Field
# Guide, issue #103.
#
# Every finding below judges ONE document: the policy component
# catalog, the platform's word on the policy components it admits —
# each versioned, signed over its digest, postured on the
# audit→warn→enforce ladder, and bound to one exact path. The joins
# live in the gate: a package binding a policy the catalog never
# declared, a binding rendered at a path the catalog never named —
# those are judged where the catalog meets the component package
# manifest. A posture the ladder never heard of is caught here,
# because a deny-by-default claim is only checkable when the record
# says which rung it sits in.
package policy

import rego.v1

import data.policy.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_findings := (((((((((((((((((f_input_invalid | f_today_invalid) | f_catalog_missing) | f_catalog_stamps) | f_policies_array) | f_policy_row_object) | f_name_required) | f_name_duplicate) | f_version_required) | f_digest_required) | f_digest_malformed) | f_signature_required) | f_signature_key_required) | f_signature_digest_required) | f_signature_digest_mismatch) | f_posture_required) | f_posture_unknown) | f_path_required) | f_path_glob

# --- findings: the input and the clock ------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the policy component catalog as input.catalog",
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

# --- findings: the catalog document ----------------------------------------------

f_catalog_missing contains finding if {
	is_object(input)
	not is_object(catalog_doc)
	finding := {
		"severity": "error",
		"rule": "catalog/missing",
		"message": "the policy component catalog is required: pass it as input.catalog — the platform's word on the policy components it admits",
		"path": "$.catalog",
	}
}

# The catalog is an owned, versioned artifact: a catalog nobody
# re-reads is a catalog of postures nobody still believes.
f_catalog_stamps contains finding if {
	is_object(catalog_doc)
	not is_positive_integer(object.get(catalog_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "catalog/version-required",
		"message": sprintf("the policy component catalog must carry a version (a positive integer): the catalog is versioned like the policies it admits (%s)", [catalog_file]),
		"path": "$.catalog.version",
	}
}

f_catalog_stamps contains finding if {
	is_object(catalog_doc)
	not lib.is_valid_date(object.get(catalog_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "catalog/reviewed-on-invalid",
		"message": sprintf("the policy component catalog must carry reviewedOn as a real YYYY-MM-DD date (%s)", [catalog_file]),
		"path": "$.catalog.reviewedOn",
	}
}

f_catalog_stamps contains finding if {
	is_object(catalog_doc)
	lib.is_valid_date(object.get(catalog_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(catalog_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "catalog/reviewed-in-future",
		"message": sprintf("the policy component catalog carries a reviewedOn date in the future (%s)", [catalog_file]),
		"path": "$.catalog.reviewedOn",
	}
}

f_catalog_stamps contains finding if {
	is_object(catalog_doc)
	lib.is_valid_date(object.get(catalog_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(catalog_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "catalog/reviewed-stale",
		"message": sprintf("the policy component catalog was reviewed more than 365 days before today: a catalog nobody re-reads is a catalog of postures nobody still believes (%s)", [catalog_file]),
		"path": "$.catalog.reviewedOn",
	}
}

f_catalog_stamps contains finding if {
	is_object(catalog_doc)
	not lib.is_nonempty_string(object.get(catalog_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "catalog/owner-required",
		"message": sprintf("the policy component catalog must name an owner: a catalog without an owner is a posture nobody maintains (%s)", [catalog_file]),
		"path": "$.catalog.owner",
	}
}

# --- findings: the policies array ---------------------------------------------------

f_policies_array contains finding if {
	is_object(catalog_doc)
	object.get(catalog_doc, "policies", null) != null
	not is_array(object.get(catalog_doc, "policies", null))
	finding := {
		"severity": "error",
		"rule": "policies/must-be-array",
		"message": sprintf("policies must be an array of the policy component rows the catalog admits (%s)", [catalog_file]),
		"path": "$.catalog.policies",
	}
}

f_policies_array contains finding if {
	is_object(catalog_doc)
	is_array(object.get(catalog_doc, "policies", null))
	count(catalog_rows) == 0
	finding := {
		"severity": "error",
		"rule": "policies/rows-required",
		"message": sprintf("the policy component catalog must admit at least one policy: a catalog of nothing admits nothing (%s)", [catalog_file]),
		"path": "$.catalog.policies",
	}
}

f_policies_array contains finding if {
	is_object(catalog_doc)
	object.get(catalog_doc, "policies", null) == null
	finding := {
		"severity": "error",
		"rule": "policies/rows-required",
		"message": sprintf("the policy component catalog must admit at least one policy: a catalog of nothing admits nothing (%s)", [catalog_file]),
		"path": "$.catalog.policies",
	}
}

f_policy_row_object contains finding if {
	some i, x in as_array(catalog_doc, "policies")
	not is_object(x)
	finding := {
		"severity": "error",
		"rule": "policies/row-must-be-object",
		"message": sprintf("policy component row %d must be an object with policy, version, digest, signature, posture, and path (%s)", [i, catalog_file]),
		"path": sprintf("$.catalog.policies[%d]", [i]),
	}
}

# --- findings: one policy component row ---------------------------------------------

f_name_required contains finding if {
	some i, x in catalog_rows
	not lib.is_nonempty_string(row_policy(x))
	finding := {
		"severity": "error",
		"rule": "policy/name-required",
		"message": sprintf("every policy component must be named: the package's bindings are joined to the catalog by name (%s)", [catalog_file]),
		"path": sprintf("$.catalog.policies[%d].policy", [i]),
	}
}

f_name_duplicate contains finding if {
	some i, x in catalog_rows
	lib.is_nonempty_string(row_policy(x))
	count([y |
		some y in catalog_rows
		lib.is_nonempty_string(row_policy(y))
		row_policy(y) == row_policy(x)
	]) > 1
	finding := {
		"severity": "error",
		"rule": "policy/name-duplicate",
		"message": sprintf("the policy component '%v' is declared more than once: one policy, one row — a policy declared twice is a posture nobody can pin down (%s)", [row_policy(x), catalog_file]),
		"path": sprintf("$.catalog.policies[%d]", [i]),
	}
}

# A policy component is versioned like any component: a version is
# how the estate says which release of a policy is in force.
f_version_required contains finding if {
	some i, x in catalog_rows
	not lib.is_nonempty_string(row_version(x))
	finding := {
		"severity": "error",
		"rule": "policy/version-required",
		"message": sprintf("every policy component must carry a version string: a policy is versioned like any component, and in force only at the version the record names (%s)", [catalog_file]),
		"path": sprintf("$.catalog.policies[%d].version", [i]),
	}
}

# A policy component is signed like any component: unsigned policy
# is policy nobody vouches for.
f_digest_required contains finding if {
	some i, x in catalog_rows
	not lib.is_nonempty_string(row_digest(x))
	finding := {
		"severity": "error",
		"rule": "policy/digest-required",
		"message": sprintf("every policy component must publish a digest of the policy artifact it ships (%s)", [catalog_file]),
		"path": sprintf("$.catalog.policies[%d].digest", [i]),
	}
}

f_digest_malformed contains finding if {
	some i, x in catalog_rows
	lib.is_nonempty_string(row_digest(x))
	not is_artifact_digest(row_digest(x))
	finding := {
		"severity": "error",
		"rule": "policy/digest-malformed",
		"message": sprintf("the policy component's digest must be a sha256 digest (64 lowercase hex characters) — '%v' is not a digest the gate agreed to read (%s)", [row_digest(x), catalog_file]),
		"path": sprintf("$.catalog.policies[%d].digest", [i]),
	}
}

f_signature_required contains finding if {
	some i, x in catalog_rows
	not is_object(row_signature(x))
	finding := {
		"severity": "error",
		"rule": "policy/signature-required",
		"message": sprintf("every policy component must be signed over the digest it publishes: an unsigned policy is a policy nobody vouches for (%s)", [catalog_file]),
		"path": sprintf("$.catalog.policies[%d].signature", [i]),
	}
}

f_signature_key_required contains finding if {
	some i, x in catalog_rows
	is_object(row_signature(x))
	not lib.is_nonempty_string(row_sig_key(row_signature(x)))
	finding := {
		"severity": "error",
		"rule": "policy/signature-key-required",
		"message": sprintf("every signature must name the key that signed it: a signature without its key is evidence nobody can trace (%s)", [catalog_file]),
		"path": sprintf("$.catalog.policies[%d].signature.keyId", [i]),
	}
}

f_signature_digest_required contains finding if {
	some i, x in catalog_rows
	is_object(row_signature(x))
	not lib.is_nonempty_string(row_sig_signed_digest(row_signature(x)))
	finding := {
		"severity": "error",
		"rule": "policy/signature-digest-required",
		"message": sprintf("the signature must record the digest it signed: a signature over nothing vouches for nothing (%s)", [catalog_file]),
		"path": sprintf("$.catalog.policies[%d].signature.signedDigest", [i]),
	}
}

# The honesty rule, inherited from the component validator (#101):
# the recorded evidence must at least be internally consistent. The
# validator does not check cryptographic validity — the key
# ceremony is outside what a policy can check.
f_signature_digest_mismatch contains finding if {
	some i, x in catalog_rows
	is_object(row_signature(x))
	lib.is_nonempty_string(row_sig_signed_digest(row_signature(x)))
	is_artifact_digest(row_digest(x))
	row_sig_signed_digest(row_signature(x)) != row_digest(x)
	finding := {
		"severity": "error",
		"rule": "policy/signature-digest-mismatch",
		"message": sprintf("the signature of '%v' records a signedDigest different from the digest the policy publishes: the recorded evidence is not even internally consistent (%s)", [row_policy(x), catalog_file]),
		"path": sprintf("$.catalog.policies[%d].signature", [i]),
	}
}

# The posture ladder: audit, warn, enforce. A posture the ladder
# never heard of is a deny-by-default claim nobody can check.
f_posture_required contains finding if {
	some i, x in catalog_rows
	not lib.is_nonempty_string(row_posture(x))
	finding := {
		"severity": "error",
		"rule": "policy/posture-required",
		"message": sprintf("every policy component must record its posture on the ladder (audit, warn, or enforce): a posture the record cannot say is a claim nobody can check (%s)", [catalog_file]),
		"path": sprintf("$.catalog.policies[%d].posture", [i]),
	}
}

f_posture_unknown contains finding if {
	some i, x in catalog_rows
	lib.is_nonempty_string(row_posture(x))
	not row_posture(x) in known_postures
	finding := {
		"severity": "error",
		"rule": "policy/posture-unknown",
		"message": sprintf("the posture of '%v' must sit on the ladder — audit, warn, or enforce — not '%v': the ladder is the estate's vocabulary, not the policy's marketing (%s)", [row_policy(x), row_posture(x), catalog_file]),
		"path": sprintf("$.catalog.policies[%d].posture", [i]),
	}
}

# The path rule: one canonical, exact path per policy component —
# no globs. The gate is honest about what it models: bindings are
# exact paths, and the join refuses to guess what a wildcard
# matched.
f_path_required contains finding if {
	some i, x in catalog_rows
	not lib.is_nonempty_string(row_path(x))
	finding := {
		"severity": "error",
		"rule": "policy/path-required",
		"message": sprintf("every policy component must be bound to its canonical path: a policy pinned to no path is a policy that can render from anywhere (%s)", [catalog_file]),
		"path": sprintf("$.catalog.policies[%d].path", [i]),
	}
}

f_path_glob contains finding if {
	some i, x in catalog_rows
	lib.is_nonempty_string(row_path(x))
	not is_exact_path(row_path(x))
	finding := {
		"severity": "error",
		"rule": "policy/path-glob",
		"message": sprintf("the path of policy component '%v' must be exact, not '%v': a glob-shaped binding is a binding the gate refuses to guess — every binding is an exact path (%s)", [row_policy(x), row_path(x), catalog_file]),
		"path": sprintf("$.catalog.policies[%d].path", [i]),
	}
}

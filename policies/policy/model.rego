# The shared model for the policy-component validation gate — The
# Software Field Guide, issue #103.
#
# Two documents enter: the POLICY COMPONENT CATALOG (the platform's
# word — the policy components it admits, each versioned, signed,
# postured on the audit→warn→enforce ladder, and bound to one exact
# path) and the COMPONENT PACKAGE MANIFEST (the package's own word,
# already known to the component validator (#101) and the
# render-matrix gate (#102) — its policyBindings section names the
# policies the package binds and the exact path each renders from).
# The join is a pair agreement: every policy a package binds must
# exist in the catalog and be bound at the catalog's declared path —
# the deny-by-default posture the package claims becomes a checkable
# fact. The gate composes on #101: the package's own conformance is
# that gate's word; this gate reads only what the policy join needs.
# Every accessor here guards its input before touching object
# fields — a malformed document must produce findings, never a
# WASM trap.
package policy

import rego.v1

import data.policy.lib

# --- the input documents ------------------------------------------------------

catalog_doc := v if {
	is_object(input)
	v := object.get(input, "catalog", null)
}

catalog_doc := null if not is_object(input)

package_doc := v if {
	is_object(input)
	v := object.get(input, "package", null)
}

package_doc := null if not is_object(input)

# The injected clock, guarded: `today` arrives with the input and is
# never read from the wall. Accessed through this accessor so a
# malformed input (an array, a string) can never trap a builtin.
today_date := v if {
	is_object(input)
	v := object.get(input, "today", null)
}

today_date := null if not is_object(input)

# The file names the findings cite, guarded the same way: the CLI and
# the playground inject them so a finding names the document it came
# from. Absent, they degrade to the definite article — a finding still
# says which document offended, just not by file name.
catalog_file := v if {
	is_object(input)
	v := object.get(input, "catalogFile", "the policy component catalog")
}

catalog_file := "the policy component catalog" if not is_object(input)

package_file := v if {
	is_object(input)
	v := object.get(input, "packageFile", "the component package manifest")
}

package_file := "the component package manifest" if not is_object(input)

# --- arrays, defensively --------------------------------------------------------

# A named array field of a document, or [] when the field is absent,
# malformed, or the document itself is not an object.
as_array(doc, key) := arr if {
	is_object(doc)
	arr := object.get(doc, key, [])
	is_array(arr)
}

as_array(doc, key) := [] if {
	is_object(doc)
	not is_array(object.get(doc, key, []))
}

as_array(doc, key) := [] if not is_object(doc)

is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# A sha256 artifact digest as the gate models it: 64 lowercase hex
# characters. Anything else is a digest the gate never agreed to
# read.
is_artifact_digest(s) if {
	is_string(s)
	regex.match(`^[a-f0-9]{64}$`, s)
}

# An exact binding path as the gate models it: a non-empty string
# with no glob metacharacters. The gate is honest about what it
# models: bindings are exact paths, `[*?[]{}]-shaped wildcards are
# refused outright — the validator's path-glob rules say so, and the
# join never has to guess what a wildcard matched.
is_exact_path(v) if {
	is_string(v)
	regex.match(`^[^*?\[\]{}]+$`, v)
}

# --- the catalog: the policy component rows -----------------------------------

# The catalog's policy rows, objects only. Malformed rows are the
# validator's findings, never an ambiguity for lookups.
catalog_rows := [x | some x in as_array(catalog_doc, "policies"); is_object(x)]

# A catalog row a join can trust: a named policy declared at one
# exact path. Version, digest, signature, and posture are the
# validator's findings; the join needs the name and the path.
row_well_formed(row) if {
	is_object(row)
	lib.is_nonempty_string(row_policy(row))
	is_exact_path(row_path(row))
}

# The well-formed catalog rows, in document order. A duplicate name
# is the validator's finding; the first row is the one the join
# reads, deterministically.
catalog_named_rows := [x | some x in catalog_rows; row_well_formed(x)]

# --- the catalog: row accessors -------------------------------------------------

row_policy(row) := object.get(row, "policy", null)

row_version(row) := object.get(row, "version", null)

row_digest(row) := object.get(row, "digest", null)

row_signature(row) := object.get(row, "signature", null)

row_sig_key(sig) := object.get(sig, "keyId", null)

row_sig_signed_digest(sig) := object.get(sig, "signedDigest", null)

row_posture(row) := object.get(row, "posture", null)

row_path(row) := object.get(row, "path", null)

# The postures the ladder knows, in order. A posture the ladder
# never heard of is a deny-by-default claim the record cannot say
# in which rung it sits.
known_postures := {"audit", "warn", "enforce"}

# Does the catalog declare a policy by this name? Judged on name
# readability alone, so a row with a broken path reports its own
# finding (policy/path-glob, policy/path-required) rather than
# silently vanishing from the join.
catalog_declares(name) if {
	some row in catalog_rows
	lib.is_nonempty_string(row_policy(row))
	row_policy(row) == name
}

# The catalog row a package binding is judged against: the first
# well-formed row declaring the binding's policy name, or nothing.
# Deterministic: a duplicate name is the validator's finding, and
# the join reads the first row.
row_for(name) := row if {
	rows := [x | some x in catalog_named_rows; row_policy(x) == name]
	count(rows) > 0
	row := rows[0]
}

# All the catalog's rows readable in full shape — the condition the
# cards render under. A malformed row anywhere is a finding, and the
# board waits until the documents can be read.
catalog_rows_readable if {
	is_object(catalog_doc)
	count(catalog_named_rows) == count(catalog_rows)
	count(catalog_rows) > 0
}

# --- the package manifest: the fields the join reads ---------------------------

# The policy gate composes on the component package conformance
# validator (#101): the package's own conformance — names, tiers,
# digests, signatures of the package itself — is that gate's word.
# This gate reads only what the policy join needs: the policy
# bindings the package declares, each a policy bound to the exact
# path it renders from.
package_bindings_present if {
	is_object(package_doc)
	object.get(package_doc, "policyBindings", null) != null
}

package_bindings := [b | some b in as_array(package_doc, "policyBindings"); is_object(b)]

binding_policy(b) := object.get(b, "policy", null)

binding_path(b) := object.get(b, "path", null)

# A binding row a join can trust: a named policy bound to one exact
# path. Shape quality beyond this is the gate's finding, never an
# ambiguity for lookups.
binding_row_well_formed(b) if {
	is_object(b)
	lib.is_nonempty_string(binding_policy(b))
	is_exact_path(binding_path(b))
}

# The well-formed declared bindings, in document order.
declared_bindings := [b | some b in package_bindings; binding_row_well_formed(b)]

# The package bindings are readable when the field is absent (the
# package declares none — an honest state, judged only against the
# bindings in force) or an array. Malformed rows are the gate's
# findings, and the join judges the well-formed subset.
package_bindings_readable if {
	not package_bindings_present
}

package_bindings_readable if {
	is_object(package_doc)
	is_array(object.get(package_doc, "policyBindings", null))
}

# The distinct bound policy names, in document order. A policy bound
# twice is the gate's finding (package/binding-duplicate), and the
# card renders once.
bound_policy_names := [name |
	some i, b in declared_bindings
	name := binding_policy(b)
	count([j |
		some j, x in declared_bindings
		j < i
		binding_policy(x) == name
	]) == 0
]

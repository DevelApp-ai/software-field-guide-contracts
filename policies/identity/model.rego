# The identity and secrets scope model — the guarded accessors the
# validator, the gate, and the audit share: the identity manifest
# (each app's declared identity and the secrets it references), the
# secrets catalog (the secrets the platform issues, the scope each
# grants, and the rotation clock each must answer to), the injected
# clock, and the file names the findings cite. Every accessor is
# guarded: a malformed `input` (an array, a string) or a malformed
# document is a finding, never a WASM trap.
package identity

import rego.v1

import data.identity.lib

# --- the input documents ------------------------------------------------------

manifest_doc := v if {
	is_object(input)
	v := object.get(input, "manifest", null)
}

manifest_doc := null if not is_object(input)
catalog_doc := v if {
	is_object(input)
	v := object.get(input, "catalog", null)
}

catalog_doc := null if not is_object(input)

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
manifest_file := v if {
	is_object(input)
	v := object.get(input, "manifestFile", "the identity manifest")
}

manifest_file := "the identity manifest" if not is_object(input)
catalog_file := v if {
	is_object(input)
	v := object.get(input, "catalogFile", "the secrets catalog")
}

catalog_file := "the secrets catalog" if not is_object(input)

# --- arrays, defensively -----------------------------------------------------

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

# A positive integer — the manifest's own version and the catalog's
# are whole numbers.
is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# A positive number — a rotation clock of zero days is no clock at all.
is_positive_number(v) if {
	is_number(v)
	v > 0
}

# --- the manifest: its house stamps -------------------------------------------

manifest_version := object.get(manifest_doc, "version", null)

manifest_reviewed_on := object.get(manifest_doc, "reviewedOn", null)

manifest_owner := object.get(manifest_doc, "owner", null)

# --- the manifest: the identities ------------------------------------------------

# The declared identity rows, guarded: only object rows are modeled;
# a malformed row is a finding, never a trap.
identity_rows := [i | some i in as_array(manifest_doc, "identities"); is_object(i)]

identity_name(i) := object.get(i, "name", null)

# The reference rows of one identity, guarded the same way.
reference_rows(i) := as_array(i, "references")

reference_secret(r) := object.get(r, "secret", null)

reference_scope(r) := object.get(r, "scope", null)

reference_since(r) := object.get(r, "since", null)

# Every reference on the manifest, carrying the identity that
# declared it and the position of the row within that identity's
# references — the shape the findings, the drifts, and the cards
# iterate.
reference_pairs := [pair |
	some identity_index, i in as_array(manifest_doc, "identities")
	is_object(i)
	some position, r in reference_rows(i)
	is_object(r)
	pair := {
		"identity": identity_name(i),
		"identityIndex": identity_index,
		"position": position,
		"row": r,
	}
]

# --- the catalog: its house stamps ----------------------------------------------
catalog_version := object.get(catalog_doc, "version", null)

catalog_reviewed_on := object.get(catalog_doc, "reviewedOn", null)

catalog_owner := object.get(catalog_doc, "owner", null)

# --- the catalog: the secrets ------------------------------------------------------

# The declared secret rows, guarded: only object rows are modeled.
secret_rows := [s | some s in as_array(catalog_doc, "secrets"); is_object(s)]

secret_name(s) := object.get(s, "name", null)

secret_kind(s) := object.get(s, "kind", null)

secret_scope(s) := object.get(s, "scope", null)

# The rotation clock: the day the secret in force today was rotated,
# and the age it may reach before the rotation is overdue.
secret_rotated_on(s) := object.get(s, "rotatedOn", null)

secret_max_age_days(s) := object.get(s, "maxAgeDays", null)

# The identities the catalog says may hold the secret — empty for a
# reserved secret, populated for every issued one.
consumer_rows(s) := [c | some c in as_array(s, "consumers"); is_string(c)]

# The secret kinds the validator agreed to model. Anything else is a
# finding — the validator judges what it can read, and refuses what
# it cannot.
modeled_kinds := {"api-key", "service-token", "signing-key", "certificate"}

kind_known(k) if k in modeled_kinds

# --- the joins ----------------------------------------------------------------

# A secret is cataloged when the catalog declares it by name.
secret_cataloged(name) if {
	some s in secret_rows
	secret_name(s) == name
}

# The catalog row for one secret by name.
cataloged_secret(name) := s if {
	some s in secret_rows
	secret_name(s) == name
}

# The catalog names an identity as a consumer of one of its secrets.
catalog_permits(identity, secret) if {
	some s in secret_rows
	secret_name(s) == secret
	some c in consumer_rows(s)
	c == identity
}

# --- the rotation clocks -----------------------------------------------------------

# The clock is readable only when the rotatedOn date and the max
# age are both readable. A clock the board cannot read is a
# finding, not a card detail.
clock_readable(s) if {
	lib.is_valid_date(secret_rotated_on(s))
	is_positive_number(secret_max_age_days(s))
}

# The age of a secret's current rotation, in days, against the
# injected clock. Only evaluated where the clock, the rotatedOn date,
# and the max age are all readable.
age_days(s) := lib.date_to_days(today_date) - lib.date_to_days(secret_rotated_on(s))

# How many days of rotation life a secret still has; negative once
# the rotation is overdue.
days_left(s) := secret_max_age_days(s) - age_days(s)

# By how many days a secret's rotation is overdue; positive when the
# clock has run out.
rotation_overdue_days(s) := age_days(s) - secret_max_age_days(s)

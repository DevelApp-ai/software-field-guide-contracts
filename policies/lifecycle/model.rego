# Field accessors for the component lifecycle evidence policies.
#
# The record and the package manifest under validation are NEVER read
# with bare field references (`input.lifecycle.foo`); these guarded
# accessors are used instead, because every one of these rules also
# has to say something honest about malformed records — a missing
# record must read as `null`, not crash the evaluation.
package lifecycle

import rego.v1

import data.lifecycle.lib

# --- input ----------------------------------------------------------------

# The component lifecycle record under validation (an object or null).
lifecycle_doc := object.get(input, "lifecycle", null)

# The component package manifest the record is judged against
# (an object or null).
package_doc := object.get(input, "package", null)

# The cut-off date for time-based rules, injected by the caller
# (a validated YYYY-MM-DD string or null).
today_date := object.get(input, "today", null)

# The caller-stated file name of the lifecycle record, quoted in every
# finding so the reader knows which file to fix (defaults are for
# tools that call the policies without stating file names).
lifecycle_file := object.get(input, "lifecycleFile", "the lifecycle record")

# The caller-stated file name of the component package manifest.
package_file := object.get(input, "packageFile", "the component package manifest")

# --- well-formedness ------------------------------------------------------

# `doc[key]` when that is an array, else an empty array
# (rows-required reports the non-array case; the empty array read here
# is well-formed enough for the rules that only count).
as_array(doc, key) := value if {
	value := object.get(doc, key, [])
	is_array(value)
}

as_array(doc, key) := [] if not is_array(object.get(doc, key, []))

# --- record accessors -----------------------------------------------------

# The record-stated component (an arbitrary value or null).
record_component := object.get(lifecycle_doc, "component", null)

# The manifest-stated component (an arbitrary value or null).
package_component := object.get(package_doc, "component", null)

# The reviewed-on stamp of the record (a validated date or null).
record_reviewed_on := object.get(lifecycle_doc, "reviewedOn", null)

record_version := object.get(lifecycle_doc, "version", null)

record_owner := object.get(lifecycle_doc, "owner", null)

# --- transition accessors -------------------------------------------------

# True when `ty` is one of the transition types the gate vouches for.
transition_type_known(ty) if ty in {"bake", "patch", "upgrade"}

# The type stamp of one recorded transition.
transition_type(t) := object.get(t, "type", null)

# The recorded-on stamp of one recorded transition.
transition_recorded_on(t) := object.get(t, "recordedOn", null)

# --- per-type evidence ----------------------------------------------------

# The bake transition's image digest (bake evidence).
bake_image_digest(t) := object.get(t, "imageDigest", null)

# The patch transition's provenance document (an object or null);
# a non-object provenance read here is null so every patch rule can
# report the shape before any field is trusted.
patch_provenance_doc(t) := value if {
	value := object.get(t, "provenance", null)
	is_object(value)
}

patch_provenance_doc(t) := null if not is_object(object.get(t, "provenance", null))

# The patch transition's source control repository.
provenance_source(t) := object.get(patch_provenance_doc(t), "source", null)

# The patch transition's source control commit.
provenance_commit(t) := object.get(patch_provenance_doc(t), "commit", null)

# The upgrade transition's rollback rehearsal document (an object or
# null; a non-object rollback read here is null for the same reason).
upgrade_rollback_doc(t) := value if {
	value := object.get(t, "rollback", null)
	is_object(value)
}

upgrade_rollback_doc(t) := null if not is_object(object.get(t, "rollback", null))

# The upgrade transition's rehearsal stamp (a validated date or null).
rollback_rehearsed_on(t) := object.get(upgrade_rollback_doc(t), "rehearsedOn", null)

# --- well-formed rows -----------------------------------------------------

# True when one recorded transition row is well-formed enough that the
# join can be asked per-row: a known type, a valid recorded-on stamp,
# and the evidence its type demands (bake: a well-formed sha256 image
# digest; patch: a provenance object with non-empty source and commit;
# upgrade: a rollback object with a valid rehearsal date). Evidence
# that is absent or malformed is reported as a finding using per-type
# rules below; this one says the row renders, not that it agrees.
row_well_formed(t) if {
	is_object(t)

	ty := transition_type(t)

	transition_type_known(ty)

	lib.is_valid_date(transition_recorded_on(t))

	row_evidence_present(t, ty)
}

row_evidence_present(t, "bake") if {
	digest := bake_image_digest(t)

	is_artifact_digest(digest)
}

row_evidence_present(t, "patch") if {
	patch_provenance_doc(t) != null

	lib.is_nonempty_string(provenance_source(t))

	lib.is_nonempty_string(provenance_commit(t))
}

row_evidence_present(t, "upgrade") if {
	upgrade_rollback_doc(t) != null

	lib.is_valid_date(rollback_rehearsed_on(t))
}

# --- helpers --------------------------------------------------------------

# True when `v` is a positive integer
# (version stamps are whole numbers human beings count: "1", "2").
is_positive_integer(v) if {
	is_number(v)

	v == floor(v)

	v >= 1
}

# True when `v` is a well-formed sha256 digest
# (64 lowercase hex characters — the artifact digest `sha256sum` prints,
# not the shortened form a human might paste).
is_artifact_digest(v) if {
	is_string(v)
	regex.match(`^[a-f0-9]{64}$`, v)
}

well_formed_rows := [t |
	some t in as_array(lifecycle_doc, "transitions")
	row_well_formed(t)
]

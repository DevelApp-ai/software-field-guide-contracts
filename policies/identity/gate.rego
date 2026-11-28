# Identity and secrets scope gate — The Software Field Guide,
# issue #108.
#
# The manifest declares the platform's identities and the secrets
# they reference; the catalog is the platform's word for the secrets
# that exist, the scope each grants, and the rotation clock each
# must answer to. This gate joins the two documents and refuses —
# a scope gate, not an advisor: a manifest that references a secret
# the catalog never declared, an identity the catalog never
# admitted among the secret's consumers, a scope the catalog never
# wrote, and a rotation clock that ran out are all refused, not
# advised. What also fails the gate is a document the gate cannot
# read — a manifest or a catalog with broken stamps or shapes is a
# question the gate refuses to answer on its own inputs. The
# verdict ladder separates the two honestly: unreadable (a
# document is malformed), drifts (only join drifts), consistent.
# The cards render the whole board: one row per declared reference,
# verdict by the join, the clock in the details.
#
# Input (JSON): {"manifest": {...}, "catalog": {...},
#                "today": "YYYY-MM-DD", "manifestFile": "...",
#                "catalogFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package identity

import rego.v1

import data.identity.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"cards": advice_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := (((((((((((validate_findings | g_catalog_missing) | g_catalog_stamps) | g_catalog_shape) | g_secret_content) | g_secret_scope) | g_rotation_clock) | g_max_age) | g_consumers) | g_reference_unresolved) | g_identity_undeclared) | g_scope_mismatch) | g_rotation_overdue

# --- findings: the secrets catalog at the gate ---------------------------------

g_catalog_missing contains finding if {
	not is_object(catalog_doc)
	finding := {
		"severity": "error",
		"rule": "catalog/missing",
		"message": "the secrets catalog is required at the gate: pass it as input.catalog — whether a secret exists at all is the catalog's word, not the manifest's",
		"path": "$.catalog",
	}
}

g_catalog_stamps contains finding if {
	is_object(catalog_doc)
	not is_positive_integer(catalog_version)
	finding := {
		"severity": "error",
		"rule": "catalog/version-required",
		"message": sprintf("the secrets catalog must carry a version (a positive integer): an unversioned catalog is a catalog nobody can pin a rotation against (%s)", [catalog_file]),
		"path": "$.catalog.version",
	}
}

g_catalog_stamps contains finding if {
	is_object(catalog_doc)
	not lib.is_valid_date(catalog_reviewed_on)
	finding := {
		"severity": "error",
		"rule": "catalog/reviewed-on-invalid",
		"message": sprintf("the secrets catalog must carry reviewedOn as a real YYYY-MM-DD date (%s)", [catalog_file]),
		"path": "$.catalog.reviewedOn",
	}
}

g_catalog_stamps contains finding if {
	is_object(catalog_doc)
	lib.is_valid_date(catalog_reviewed_on)
	lib.is_valid_date(today_date)
	lib.date_to_days(catalog_reviewed_on) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "catalog/reviewed-in-future",
		"message": sprintf("the secrets catalog carries a reviewedOn date in the future (%s)", [catalog_file]),
		"path": "$.catalog.reviewedOn",
	}
}

g_catalog_stamps contains finding if {
	is_object(catalog_doc)
	lib.is_valid_date(catalog_reviewed_on)
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(catalog_reviewed_on) > 365
	finding := {
		"severity": "error",
		"rule": "catalog/reviewed-stale",
		"message": sprintf("the secrets catalog was reviewed more than 365 days before today: the platform's secrets changed since, and this document says nothing about it (%s)", [catalog_file]),
		"path": "$.catalog.reviewedOn",
	}
}

g_catalog_stamps contains finding if {
	is_object(catalog_doc)
	not lib.is_nonempty_string(catalog_owner)
	finding := {
		"severity": "error",
		"rule": "catalog/owner-required",
		"message": sprintf("the secrets catalog must name an owner: a catalog with an owner and a review cadence is the discipline (%s)", [catalog_file]),
		"path": "$.catalog.owner",
	}
}

g_catalog_shape contains finding if {
	is_object(catalog_doc)
	not is_array(object.get(catalog_doc, "secrets", null))
	finding := {
		"severity": "error",
		"rule": "catalog/secrets-must-be-array",
		"message": sprintf("the secrets catalog's secrets must be an array of {name, kind, scope, rotatedOn, maxAgeDays, consumers} rows (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_catalog_shape contains finding if {
	is_object(catalog_doc)
	is_array(object.get(catalog_doc, "secrets", null))
	some s in object.get(catalog_doc, "secrets", [])
	not is_object(s)
	finding := {
		"severity": "error",
		"rule": "catalog/secret-must-be-object",
		"message": sprintf("every secret row must be an object: {name, kind, scope, rotatedOn, maxAgeDays, consumers} (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

# --- findings: each cataloged secret's own words -------------------------------

g_secret_content contains finding if {
	some s in secret_rows
	not lib.is_nonempty_string(secret_name(s))
	finding := {
		"severity": "error",
		"rule": "secret/name-required",
		"message": sprintf("every secret row must name the secret: an unnamed secret is a grant nobody can scope (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_secret_content contains finding if {
	some s in secret_rows
	lib.is_nonempty_string(secret_name(s))
	count([x | some x in secret_rows; secret_name(x) == secret_name(s)]) > 1
	finding := {
		"severity": "error",
		"rule": "secret/name-duplicate",
		"message": sprintf("the secret '%v' is declared more than once: one secret, one row (%s)", [secret_name(s), catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_secret_content contains finding if {
	some s in secret_rows
	not lib.is_nonempty_string(secret_kind(s))
	finding := {
		"severity": "error",
		"rule": "secret/kind-required",
		"message": sprintf("every secret row must name its kind: how a credential authenticates decides how it must be rotated (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_secret_content contains finding if {
	some s in secret_rows
	lib.is_nonempty_string(secret_kind(s))
	not kind_known(secret_kind(s))
	finding := {
		"severity": "error",
		"rule": "secret/kind-unknown",
		"message": sprintf("the secret '%v' names the kind '%v', which the validator never agreed to model: api-key, service-token, signing-key, certificate (%s)", [secret_name(s), secret_kind(s), catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_secret_scope contains finding if {
	some s in secret_rows
	not lib.is_nonempty_string(secret_scope(s))
	finding := {
		"severity": "error",
		"rule": "secret/scope-required",
		"message": sprintf("every cataloged secret must carry the scope it grants: a secret that means everything is a breach nobody can bound (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_secret_scope contains finding if {
	some s in secret_rows
	secret_scope(s) == "*"
	finding := {
		"severity": "error",
		"rule": "secret/scope-wildcard",
		"message": sprintf("the secret '%v' carries the wildcard scope '*': the catalog exists to name grants, not to grant everything (%s)", [secret_name(s), catalog_file]),
		"path": "$.catalog.secrets",
	}
}

# --- findings: the rotation clock each secret must answer to --------------------

g_rotation_clock contains finding if {
	some s in secret_rows
	secret_rotated_on(s) == null
	finding := {
		"severity": "error",
		"rule": "secret/rotated-on-required",
		"message": sprintf("the secret '%v' carries no rotation clock: rotatedOn and maxAgeDays are how a leaked credential ages out of usefulness — a secret with no rotation clock is a credential the platform holds forever (%s)", [secret_name(s), catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_rotation_clock contains finding if {
	some s in secret_rows
	secret_rotated_on(s) != null
	not lib.is_valid_date(secret_rotated_on(s))
	finding := {
		"severity": "error",
		"rule": "secret/rotated-on-invalid",
		"message": sprintf("every cataloged secret must carry rotatedOn as a real YYYY-MM-DD date (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_rotation_clock contains finding if {
	some s in secret_rows
	lib.is_valid_date(secret_rotated_on(s))
	lib.is_valid_date(today_date)
	lib.date_to_days(secret_rotated_on(s)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "secret/rotated-in-future",
		"message": sprintf("the secret '%v' carries a rotatedOn date in the future: a rotation that has not happened is a clock that has not started (%s)", [secret_name(s), catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_max_age contains finding if {
	some s in secret_rows
	secret_max_age_days(s) == null
	finding := {
		"severity": "error",
		"rule": "secret/max-age-required",
		"message": sprintf("every cataloged secret must carry the age its rotation may reach (maxAgeDays): a clock with nothing to measure against never rings (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_max_age contains finding if {
	some s in secret_rows
	secret_max_age_days(s) != null
	not is_positive_number(secret_max_age_days(s))
	finding := {
		"severity": "error",
		"rule": "secret/max-age-invalid",
		"message": sprintf("the rotation clock's maxAgeDays must be a positive number of days — a zero-day clock is a rotation schedule nobody can keep (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

# --- findings: the consumers the catalog admits ---------------------------------

g_consumers contains finding if {
	some s in secret_rows
	not is_array(object.get(s, "consumers", null))
	finding := {
		"severity": "error",
		"rule": "secret/consumers-must-be-array",
		"message": sprintf("every cataloged secret must name its consumers as an array of identity names (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_consumers contains finding if {
	some s in secret_rows
	is_array(object.get(s, "consumers", null))
	some c in object.get(s, "consumers", [])
	not is_string(c)
	finding := {
		"severity": "error",
		"rule": "secret/consumers-must-be-array",
		"message": sprintf("every cataloged secret must name its consumers as an array of identity names (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_consumers contains finding if {
	some s in secret_rows
	some c in consumer_rows(s)
	not lib.is_nonempty_string(c)
	finding := {
		"severity": "error",
		"rule": "secret/consumer-required",
		"message": sprintf("every consumer name must be a non-empty string: a consumer nobody can name is permission nobody can revoke (%s)", [catalog_file]),
		"path": "$.catalog.secrets",
	}
}

g_consumers contains finding if {
	some s in secret_rows
	some c in consumer_rows(s)
	count([x | some x in consumer_rows(s); x == c]) > 1
	finding := {
		"severity": "error",
		"rule": "secret/consumer-duplicate",
		"message": sprintf("the secret '%v' names the consumer '%v' more than once: one identity, one entry (%s)", [secret_name(s), c, catalog_file]),
		"path": "$.catalog.secrets",
	}
}

# --- the four drifts, named ------------------------------------------------------

# (1) The unresolved reference: the manifest names a secret the
# catalog never declared. A reference to a secret that does not
# exist is either catalog drift or a secret that bypassed the
# platform — both are refused.
g_reference_unresolved contains finding if {
	is_object(manifest_doc)
	is_object(catalog_doc)
	some p in reference_pairs
	lib.is_nonempty_string(reference_secret(p.row))
	not secret_cataloged(reference_secret(p.row))
	finding := {
		"severity": "error",
		"rule": "gate/reference-unresolved",
		"message": sprintf("the identity '%v' references the secret '%v', which the catalog never declares: a reference the catalog cannot vouch for is a secret outside the platform's word (%s, %s)", [p.identity, reference_secret(p.row), manifest_file, catalog_file]),
		"path": "$.manifest.identities",
	}
}

# (2) The undeclared identity: the reference is well-formed and the
# secret exists, but the catalog never admitted this identity among
# its consumers. Deny by default — being a consumer is granted, not
# assumed.
g_identity_undeclared contains finding if {
	is_object(manifest_doc)
	is_object(catalog_doc)
	some p in reference_pairs
	lib.is_nonempty_string(p.identity)
	lib.is_nonempty_string(reference_secret(p.row))
	secret_cataloged(reference_secret(p.row))
	not catalog_permits(p.identity, reference_secret(p.row))
	finding := {
		"severity": "error",
		"rule": "gate/identity-undeclared",
		"message": sprintf("the identity '%v' references the secret '%v', but the catalog does not name it among the secret's consumers: permission is granted by the catalog, never assumed by the manifest (%s, %s)", [p.identity, reference_secret(p.row), manifest_file, catalog_file]),
		"path": "$.manifest.identities",
	}
}

# (3) The scope mismatch: the reference claims a scope the catalog
# never wrote. Judged by equality — glob shapes were already refused
# at validation — and guarded so a scope the manifest never narrowed
# is an unreadable document, not a fancy drift.
g_scope_mismatch contains finding if {
	is_object(manifest_doc)
	is_object(catalog_doc)
	some p in reference_pairs
	lib.is_nonempty_string(reference_secret(p.row))
	secret_cataloged(reference_secret(p.row))
	lib.is_nonempty_string(reference_scope(p.row))
	reference_scope(p.row) != "*"
	count([c | some c in ["*", "?", "["]; contains(reference_scope(p.row), c)]) == 0
	lib.is_nonempty_string(secret_scope(cataloged_secret(reference_secret(p.row))))
	reference_scope(p.row) != secret_scope(cataloged_secret(reference_secret(p.row)))
	finding := {
		"severity": "error",
		"rule": "gate/scope-mismatch",
		"message": sprintf("the identity '%v' references the secret '%v' at scope '%v', but the catalog grants '%v': scope minimality is the catalog's word, not the manifest's ambition (%s, %s)", [p.identity, reference_secret(p.row), reference_scope(p.row), secret_scope(cataloged_secret(reference_secret(p.row))), manifest_file, catalog_file]),
		"path": "$.manifest.identities",
	}
}

# (4) The overdue rotation: the secret's clock ran out. The finding
# cites the secret, the day it last rotated, the age it promised not
# to reach, and by how many days the platform let it slip.
g_rotation_overdue contains finding if {
	is_object(manifest_doc)
	is_object(catalog_doc)
	some s in secret_rows
	lib.is_nonempty_string(secret_name(s))
	lib.is_valid_date(secret_rotated_on(s))
	lib.is_valid_date(today_date)
	is_positive_number(secret_max_age_days(s))
	rotation_overdue_days(s) > 0
	finding := {
		"severity": "error",
		"rule": "gate/rotation-overdue",
		"message": sprintf("the secret '%v' was last rotated on %v and its %v-day clock ran out %v days ago: a credential the platform holds past its rotation clock is a credential attackers get extra time with (%s)", [secret_name(s), secret_rotated_on(s), secret_max_age_days(s), round(rotation_overdue_days(s)), catalog_file]),
		"path": "$.catalog.secrets",
	}
}

# --- the cards -----------------------------------------------------------------

# The board: one row per well-formed declared reference, verdict by
# the join, the clock in the details. Only references the manifest
# wrote legibly render; a malformed clause is a finding, not a card.
advice_cards := sort([card |
	some p in reference_pairs
	lib.is_nonempty_string(p.identity)
	lib.is_nonempty_string(reference_secret(p.row))
	card := {
		"area": "references",
		"item": sprintf("%v/%v", [p.identity, reference_secret(p.row)]),
		"verdict": reference_card_verdict(p),
		"detail": reference_card_detail(p),
	}
])

reference_card_verdict(p) := "consistent" if reference_consistent(p)

reference_card_verdict(p) := "drifts" if not reference_consistent(p)

# A reference is consistent when the catalog declares the secret,
# admits the identity, grants exactly the scope the reference
# claims, and the secret's rotation clock is readable and has not
# run out.
reference_consistent(p) if {
	secret_cataloged(reference_secret(p.row))
	catalog_permits(p.identity, reference_secret(p.row))
	reference_scope(p.row) == secret_scope(cataloged_secret(reference_secret(p.row)))
	clock_readable(cataloged_secret(reference_secret(p.row)))
	not rotation_overdue(cataloged_secret(reference_secret(p.row)))
}

rotation_overdue(s) if {
	lib.is_valid_date(secret_rotated_on(s))
	lib.is_valid_date(today_date)
	is_positive_number(secret_max_age_days(s))
	rotation_overdue_days(s) > 0
}

reference_card_detail(p) := detail if {
	reference_consistent(p)
	s := cataloged_secret(reference_secret(p.row))
	detail := sprintf("the catalog admits '%v' to '%v' at scope '%v', rotated %v with %v days left on the clock (%s, %s)", [
		p.identity,
		reference_secret(p.row),
		secret_scope(s),
		secret_rotated_on(s),
		days_left(s),
		manifest_file,
		catalog_file,
	])
}

reference_card_detail(p) := sprintf("the catalog does not vouch for this reference (%s, %s)", [manifest_file, catalog_file]) if {
	not secret_cataloged(reference_secret(p.row))
}

reference_card_detail(p) := detail if {
	secret_cataloged(reference_secret(p.row))
	not catalog_permits(p.identity, reference_secret(p.row))
	detail := sprintf("the catalog names the secret '%v' but not the identity '%v' among its consumers (%s, %s)", [
		reference_secret(p.row),
		p.identity,
		manifest_file,
		catalog_file,
	])
}

reference_card_detail(p) := detail if {
	secret_cataloged(reference_secret(p.row))
	catalog_permits(p.identity, reference_secret(p.row))
	reference_scope(p.row) != secret_scope(cataloged_secret(reference_secret(p.row)))
	detail := sprintf("the reference claims scope '%v', the catalog grants '%v' (%s, %s)", [
		reference_scope(p.row),
		secret_scope(cataloged_secret(reference_secret(p.row))),
		manifest_file,
		catalog_file,
	])
}

reference_card_detail(p) := detail if {
	secret_cataloged(reference_secret(p.row))
	catalog_permits(p.identity, reference_secret(p.row))
	reference_scope(p.row) == secret_scope(cataloged_secret(reference_secret(p.row)))
	rotation_overdue(cataloged_secret(reference_secret(p.row)))
	detail := sprintf("the secret '%v' is %v days past its rotation clock, last rotated %v (%s, %s)", [
		reference_secret(p.row),
		round(rotation_overdue_days(cataloged_secret(reference_secret(p.row)))),
		secret_rotated_on(cataloged_secret(reference_secret(p.row))),
		manifest_file,
		catalog_file,
	])
}

reference_card_detail(p) := detail if {
	not reference_consistent(p)
	secret_cataloged(reference_secret(p.row))
	catalog_permits(p.identity, reference_secret(p.row))
	reference_scope(p.row) == secret_scope(cataloged_secret(reference_secret(p.row)))
	not rotation_overdue(cataloged_secret(reference_secret(p.row)))
	detail := sprintf("the catalog admits '%v' to '%v', but its rotation clock is not readable — see the findings (%s, %s)", [
		p.identity,
		reference_secret(p.row),
		manifest_file,
		catalog_file,
	])
}

# --- the verdict ladder -----------------------------------------------------------

# The scope ladder, honest about what each rung means: a
# document the gate cannot read is a question the gate refuses to
# answer; drifts are scope failures the platform must fix before the
# manifest is believed; a manifest whose every reference the catalog
# vouches for, at the scope it grants, inside a live rotation clock,
# is consistent.
gate_verdict(fs) := "unreadable" if {
	some f in fs
	not startswith(f.rule, "gate/")
}

gate_verdict(fs) := "drifts" if {
	count([f | some f in fs; not startswith(f.rule, "gate/")]) == 0
	count(fs) > 0
}

gate_verdict(fs) := "consistent" if {
	count(fs) == 0
}

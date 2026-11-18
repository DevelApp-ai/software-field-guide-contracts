# The component package manifest validated alone — The Software
# Field Guide, issue #101.
#
# Every finding below judges ONE document: the component package
# manifest, the package recorded as data — its name, version, and
# tier, the artifact digest it publishes, the signature and
# attestation recorded over that digest, its provenance, and the
# dependencies it pins by digest. The validator is honest about what
# it models: it checks the evidence facts are RECORDED and internally
# consistent (the signed digest equals the artifact digest), not
# that signatures are cryptographically valid — that verification
# lives in the signing infrastructure, not in policy. The joins live
# in the gate: an unregistered package, an artifact that drifted
# from its registration, a dependency the registry never admitted,
# a stale pin, and a tier violated downward are all judged where
# the package meets the registry.
package component

import rego.v1

import data.component.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_findings := (((((((((((((f_input_invalid | f_today_invalid) | f_package_missing) | f_package_stamps) | f_component_content) | f_artifact) | f_signature) | f_attestation) | f_provenance) | f_dependencies_shape) | f_dependency_name) | f_dependency_digest) | f_dependency_malformed) | f_dependency_duplicate) | f_dependency_general

# --- findings: the input and the clock -----------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the component package manifest as input.package",
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

# --- findings: the package manifest document --------------------------------------

f_package_missing contains finding if {
	not is_object(package_doc)
	finding := {
		"severity": "error",
		"rule": "package/missing",
		"message": "the component package manifest is required: pass it as input.package",
		"path": "$.package",
	}
}

f_package_stamps contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(object.get(package_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "package/version-required",
		"message": sprintf("the package manifest must carry a version string (e.g. \"1.4.0\"): the registry registers component+version, and drift is judged per version (%s)", [package_file]),
		"path": "$.package.version",
	}
}

f_package_stamps contains finding if {
	is_object(package_doc)
	not lib.is_valid_date(object.get(package_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "package/reviewed-on-invalid",
		"message": sprintf("the package manifest must carry reviewedOn as a real YYYY-MM-DD date (%s)", [package_file]),
		"path": "$.package.reviewedOn",
	}
}

f_package_stamps contains finding if {
	is_object(package_doc)
	lib.is_valid_date(object.get(package_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(package_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "package/reviewed-in-future",
		"message": sprintf("the package manifest carries a reviewedOn date in the future (%s)", [package_file]),
		"path": "$.package.reviewedOn",
	}
}

f_package_stamps contains finding if {
	is_object(package_doc)
	lib.is_valid_date(object.get(package_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(package_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "package/reviewed-stale",
		"message": sprintf("the package manifest was reviewed more than 365 days before today: this manifest says nothing about the package that changed since (%s)", [package_file]),
		"path": "$.package.reviewedOn",
	}
}

f_package_stamps contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(object.get(package_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "package/owner-required",
		"message": sprintf("the package manifest must name an owner: a package with an owner and a review cadence is the discipline (%s)", [package_file]),
		"path": "$.package.owner",
	}
}

# --- findings: the package's identity ----------------------------------------------

f_component_content contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(package_name)
	finding := {
		"severity": "error",
		"rule": "component/name-required",
		"message": sprintf("the package manifest must name the component it packages: the registry admits packages by name (%s)", [package_file]),
		"path": "$.package.component",
	}
}

f_component_content contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(package_hierarchy)
	finding := {
		"severity": "error",
		"rule": "hierarchy/required",
		"message": sprintf("the package manifest must declare its tier: general, customer, or project — the tier decides what it may depend on (%s)", [package_file]),
		"path": "$.package.hierarchy",
	}
}

f_component_content contains finding if {
	is_object(package_doc)
	lib.is_nonempty_string(package_hierarchy)
	not hierarchy_known(package_hierarchy)
	finding := {
		"severity": "error",
		"rule": "hierarchy/unknown",
		"message": sprintf("the package declares the tier '%v', which the validator never agreed to model: general, customer, or project (%s)", [package_hierarchy, package_file]),
		"path": "$.package.hierarchy",
	}
}

# --- findings: the artifact digest ---------------------------------------------------

f_artifact contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(object.get(package_doc, "artifactDigest", null))
	finding := {
		"severity": "error",
		"rule": "artifact/digest-required",
		"message": sprintf("the package manifest must publish an artifactDigest: a package without a digest is a name, not an artifact (%s)", [package_file]),
		"path": "$.package.artifactDigest",
	}
}

f_artifact contains finding if {
	is_object(package_doc)
	lib.is_nonempty_string(object.get(package_doc, "artifactDigest", null))
	not is_artifact_digest(object.get(package_doc, "artifactDigest", null))
	finding := {
		"severity": "error",
		"rule": "artifact/digest-malformed",
		"message": sprintf("the artifactDigest must be a sha256 digest (64 lowercase hex characters) — '%v' is not a digest the gate agreed to read (%s)", [object.get(package_doc, "artifactDigest", null), package_file]),
		"path": "$.package.artifactDigest",
	}
}

# --- findings: the recorded signature ---------------------------------------------

f_signature contains finding if {
	is_object(package_doc)
	not is_object(object.get(package_doc, "signature", null))
	finding := {
		"severity": "error",
		"rule": "signature/required",
		"message": sprintf("the package manifest must record a signature over the artifact digest: an unsigned artifact is an artifact nobody vouches for (%s)", [package_file]),
		"path": "$.package.signature",
	}
}

f_signature contains finding if {
	is_object(signature_doc)
	not lib.is_nonempty_string(signature_key_id)
	finding := {
		"severity": "error",
		"rule": "signature/key-required",
		"message": sprintf("the signature must name the key that signed (keyId) (%s)", [package_file]),
		"path": "$.package.signature.keyId",
	}
}

f_signature contains finding if {
	is_object(signature_doc)
	not lib.is_nonempty_string(signature_signed_digest)
	finding := {
		"severity": "error",
		"rule": "signature/digest-required",
		"message": sprintf("the signature must record what it signed (signedDigest) (%s)", [package_file]),
		"path": "$.package.signature.signedDigest",
	}
}

# The conformance the validator can check honestly: the signed
# digest is the artifact digest. That the signature is
# cryptographically valid is the signing infrastructure's word, not
# policy's.
f_signature contains finding if {
	is_object(signature_doc)
	lib.is_nonempty_string(signature_signed_digest)
	lib.is_nonempty_string(object.get(package_doc, "artifactDigest", null))
	signature_signed_digest != object.get(package_doc, "artifactDigest", null)
	finding := {
		"severity": "error",
		"rule": "signature/digest-mismatch",
		"message": sprintf("the signature's signedDigest does not equal the artifactDigest: the recorded evidence is not even internally consistent (%s)", [package_file]),
		"path": "$.package.signature.signedDigest",
	}
}

# --- findings: the recorded attestation and provenance ------------------------------

f_attestation contains finding if {
	is_object(package_doc)
	not is_object(object.get(package_doc, "attestation", null))
	finding := {
		"severity": "error",
		"rule": "attestation/required",
		"message": sprintf("the package manifest must record an attestation: what the package claims to be, and who checked (%s)", [package_file]),
		"path": "$.package.attestation",
	}
}

f_attestation contains finding if {
	is_object(attestation_doc)
	not lib.is_nonempty_string(attestation_statement)
	finding := {
		"severity": "error",
		"rule": "attestation/statement-required",
		"message": sprintf("the attestation must say something (statement): 'no comment' is not an attestation (%s)", [package_file]),
		"path": "$.package.attestation.statement",
	}
}

f_attestation contains finding if {
	is_object(attestation_doc)
	not lib.is_nonempty_string(attestation_by)
	finding := {
		"severity": "error",
		"rule": "attestation/by-required",
		"message": sprintf("the attestation must name who attested (by): a claim without a claimant is nobody's word (%s)", [package_file]),
		"path": "$.package.attestation.by",
	}
}

f_provenance contains finding if {
	is_object(package_doc)
	not is_object(object.get(package_doc, "provenance", null))
	finding := {
		"severity": "error",
		"rule": "provenance/required",
		"message": sprintf("the package manifest must record provenance: where the artifact came from, and which commit built it (%s)", [package_file]),
		"path": "$.package.provenance",
	}
}

f_provenance contains finding if {
	is_object(provenance_doc)
	not lib.is_nonempty_string(provenance_source)
	finding := {
		"severity": "error",
		"rule": "provenance/source-required",
		"message": sprintf("the provenance must name the source the artifact was built from (%s)", [package_file]),
		"path": "$.package.provenance.source",
	}
}

f_provenance contains finding if {
	is_object(provenance_doc)
	not lib.is_nonempty_string(provenance_commit)
	finding := {
		"severity": "error",
		"rule": "provenance/commit-required",
		"message": sprintf("the provenance must name the commit the artifact was built from: an artifact without a commit is an artifact nobody can rebuild (%s)", [package_file]),
		"path": "$.package.provenance.commit",
	}
}

# --- findings: the pinned dependencies -----------------------------------------------

f_dependencies_shape contains finding if {
	is_object(package_doc)
	not is_array(object.get(package_doc, "dependencies", null))
	finding := {
		"severity": "error",
		"rule": "dependencies/must-be-array",
		"message": sprintf("the package manifest's dependencies must be an array of {package, digest} rows (%s)", [package_file]),
		"path": "$.package.dependencies",
	}
}

f_dependencies_shape contains finding if {
	is_object(package_doc)
	is_array(object.get(package_doc, "dependencies", null))
	some d in object.get(package_doc, "dependencies", [])
	not is_object(d)
	finding := {
		"severity": "error",
		"rule": "dependencies/row-must-be-object",
		"message": sprintf("every dependency row must be an object: {package, digest} (%s)", [package_file]),
		"path": "$.package.dependencies",
	}
}

f_dependency_name contains finding if {
	some d in dependencies
	not lib.is_nonempty_string(dependency_name(d))
	finding := {
		"severity": "error",
		"rule": "dependency/name-required",
		"message": sprintf("every dependency must name the package it depends on (%s)", [package_file]),
		"path": "$.package.dependencies",
	}
}

f_dependency_digest contains finding if {
	some d in dependencies
	not lib.is_nonempty_string(dependency_digest(d))
	finding := {
		"severity": "error",
		"rule": "dependency/digest-required",
		"message": sprintf("every dependency must pin a digest: a dependency pinned by name alone is a dependency that can change under the package (%s)", [package_file]),
		"path": "$.package.dependencies",
	}
}

f_dependency_malformed contains finding if {
	some d in dependencies
	lib.is_nonempty_string(dependency_digest(d))
	not is_artifact_digest(dependency_digest(d))
	finding := {
		"severity": "error",
		"rule": "dependency/digest-malformed",
		"message": sprintf("every dependency digest must be a sha256 digest (64 lowercase hex characters) — '%v' is not a digest the gate agreed to read (%s)", [dependency_digest(d), package_file]),
		"path": "$.package.dependencies",
	}
}

f_dependency_duplicate contains finding if {
	some d in dependencies
	lib.is_nonempty_string(dependency_name(d))
	count([x | some x in dependencies; dependency_name(x) == dependency_name(d)]) > 1
	finding := {
		"severity": "error",
		"rule": "dependency/duplicate",
		"message": sprintf("the dependency '%v' is declared more than once: one package, one row (%s)", [dependency_name(d), package_file]),
		"path": "$.package.dependencies",
	}
}

# A general-tier package declaring any dependency: the baseline
# everything else builds on depends on nothing. The tier is a
# promise, and this is where it is kept.
f_dependency_general contains finding if {
	is_object(package_doc)
	package_hierarchy == "general"
	count(dependencies) > 0
	finding := {
		"severity": "error",
		"rule": "dependency/general-forbidden",
		"message": sprintf("a general-tier package must declare no dependencies: the baseline everything else builds on depends on nothing (%s)", [package_file]),
		"path": "$.package.dependencies",
	}
}

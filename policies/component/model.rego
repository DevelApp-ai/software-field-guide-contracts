# The shared model for the component package conformance validator —
# The Software Field Guide, issue #101.
#
# Two documents enter: the COMPONENT PACKAGE MANIFEST (the package as
# data — its name, version, and tier, the artifact digest it
# publishes, the signature and attestation recorded over that
# digest, its provenance, and the dependencies it pins by digest)
# and the COMPONENT REGISTRY (the estate's word — the packages it
# has admitted, each as a component, version, tier, and digest
# row). The validator models a stated subset honestly: it checks the
# evidence facts are RECORDED and internally consistent (the signed
# digest equals the artifact digest, the pins equal the registry's
# digests) — not that signatures are cryptographically valid. Every
# accessor here guards its input before touching object fields — a
# malformed document must produce findings, never a WASM trap.
package component

import rego.v1

import data.component.lib

# --- the input documents ------------------------------------------------------

package_doc := v if {
	is_object(input)
	v := object.get(input, "package", null)
}

package_doc := null if not is_object(input)

registry_doc := v if {
	is_object(input)
	v := object.get(input, "registry", null)
}

registry_doc := null if not is_object(input)

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
package_file := v if {
	is_object(input)
	v := object.get(input, "packageFile", "the component package manifest")
}

package_file := "the component package manifest" if not is_object(input)

registry_file := v if {
	is_object(input)
	v := object.get(input, "registryFile", "the component registry")
}

registry_file := "the component registry" if not is_object(input)

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

# A positive integer — the registry's own version is a whole number.
is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# --- the package manifest: its identity ----------------------------------------

package_name := object.get(package_doc, "component", null)

package_version := object.get(package_doc, "version", null)

# The three tiers the validator models: a general-tier package is
# the baseline everything else may build on; a customer-tier package
# builds on general and customer; a project-tier package builds on
# anything. The direction is one-way — a customer-tier package
# depending on a project-tier package is a package pretending to be
# more reusable than it is.
package_hierarchy := object.get(package_doc, "hierarchy", null)

hierarchy_known(h) if h in {"general", "customer", "project"}

# A sha256 artifact digest as the validator models it: 64 lowercase
# hex characters. Anything else is a digest the gate never agreed to
# read.
is_artifact_digest(s) if {
	is_string(s)
	regex.match(`^[a-f0-9]{64}$`, s)
}

# --- the package manifest: the evidence over the artifact ------------------------

# The recorded signature, guarded: an object or nothing. A signature
# that is not an object is a finding, never a trap.
signature_doc := v if {
	is_object(package_doc)
	v := object.get(package_doc, "signature", null)
	is_object(v)
}

signature_doc := null if {
	is_object(package_doc)
	not is_object(object.get(package_doc, "signature", null))
}

signature_doc := null if not is_object(package_doc)

signature_key_id := object.get(signature_doc, "keyId", null)

signature_signed_digest := object.get(signature_doc, "signedDigest", null)

# The recorded attestation and provenance, guarded the same way.
attestation_doc := v if {
	is_object(package_doc)
	v := object.get(package_doc, "attestation", null)
	is_object(v)
}

attestation_doc := null if {
	is_object(package_doc)
	not is_object(object.get(package_doc, "attestation", null))
}

attestation_doc := null if not is_object(package_doc)

attestation_statement := object.get(attestation_doc, "statement", null)

attestation_by := object.get(attestation_doc, "by", null)

provenance_doc := v if {
	is_object(package_doc)
	v := object.get(package_doc, "provenance", null)
	is_object(v)
}

provenance_doc := null if {
	is_object(package_doc)
	not is_object(object.get(package_doc, "provenance", null))
}

provenance_doc := null if not is_object(package_doc)

provenance_source := object.get(provenance_doc, "source", null)

provenance_commit := object.get(provenance_doc, "commit", null)

# --- the package manifest: the pinned dependencies -------------------------------

dependencies := [d | some d in as_array(package_doc, "dependencies"); is_object(d)]

dependency_name(d) := object.get(d, "package", null)

dependency_digest(d) := object.get(d, "digest", null)

# --- the registry: the estate's admitted packages ---------------------------------

registry_rows := [r | some r in as_array(registry_doc, "packages"); is_object(r)]

row_component(r) := object.get(r, "component", null)

row_version(r) := object.get(r, "version", null)

row_hierarchy(r) := object.get(r, "hierarchy", null)

row_digest(r) := object.get(r, "digest", null)

# A package is registered when the registry carries a row for that
# component at that version — registration is per component+version,
# because the digest is.
row_registered(name, version) if {
	some r in registry_rows
	row_component(r) == name
	row_version(r) == version
}

row_for(name, version) := r if {
	some r in registry_rows
	row_component(r) == name
	row_version(r) == version
}

# A dependency is resolved when the registry carries any row for
# that package name, and pinned when one of those rows carries the
# exact digest the manifest pins.
dependency_resolved(name) if {
	some r in registry_rows
	row_component(r) == name
}

dependency_pinned(name, digest) if {
	some r in registry_rows
	row_component(r) == name
	row_digest(r) == digest
}

# The tier direction, judged at the gate against the registry's own
# word: a customer-tier package may build on general or customer; a
# project-tier package may build on anything. A general-tier package
# declaring any dependency at all is refused at validation — the
# baseline depends on nothing.
hierarchy_allows(package_tier, dep_tier) if package_tier == "project"

hierarchy_allows(package_tier, dep_tier) if {
	package_tier == "customer"
	dep_tier in {"general", "customer"}
}

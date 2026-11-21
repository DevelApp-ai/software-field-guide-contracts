# The shared model for the supply-chain IAM-broker scope gate —
# The Software Field Guide, issue #104.
#
# Two documents enter: the BROKER GRANT DOCUMENT (the broker's word
# — the consumer identities it declares, and every grant it issued:
# each grant naming one declared principal, one component pinned by
# sha256 digest, the allowed action set, and an expiry) and the
# COMPONENT PACKAGE MANIFEST (the package's own word — the
# component it packages, the artifact digest it publishes, and the
# dependencies it pins by digest). The join is the supply-chain
# chokepoint: every grant's component reference must resolve to a
# manifest entry — the package itself or one of its pinned
# dependencies — at exactly the digest the grant pins. A grant for
# a component the manifest never named is a claim nobody can check;
# a grant pinning a different digest is a grant for bytes the
# package never published. The gate composes on the component
# package conformance validator (#101): the package's own
# conformance is that gate's word. Every accessor here guards its
# input before touching object fields — a malformed document must
# produce findings, never a WASM trap.
package broker

import rego.v1

import data.broker.lib

# --- the input documents ------------------------------------------------------

broker_doc := v if {
	is_object(input)
	v := object.get(input, "broker", null)
}

broker_doc := null if not is_object(input)

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
broker_file := v if {
	is_object(input)
	v := object.get(input, "brokerFile", "the broker grant document")
}

broker_file := "the broker grant document" if not is_object(input)

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

# --- the broker grant document: the declared principals ---------------------------

# The consumer identities the broker declares, and a name is
# declared when it appears there. A grant without a declared
# consumer identity is a grant nobody answers for.
principal_entries := [p | some p in as_array(broker_doc, "principals")]

declared_principals := sort({p |
	some p in principal_entries
	lib.is_nonempty_string(p)
})

principal_declared(principal) if {
	some p in declared_principals
	p == principal
}

# --- the broker grant document: the grant rows -------------------------------------

grant_rows := [g | some g in as_array(broker_doc, "grants"); is_object(g)]

grant_principal(g) := object.get(g, "principal", null)

grant_component(g) := object.get(g, "component", null)

grant_digest(g) := object.get(g, "digest", null)

grant_action_rows(g) := [a | some a in as_array(g, "actions"); is_string(a)]

grant_expires(g) := object.get(g, "expires", null)

# A grant row the cards can name: its principal and its component
# both non-empty strings. The digest, the actions, and the expiry
# have their own findings — this readable pair is the identity the
# join and the cards cite.
grant_row_readable(g) if {
	is_object(g)
	lib.is_nonempty_string(grant_principal(g))
	lib.is_nonempty_string(grant_component(g))
}

# The well-formed grant rows, in document order.
readable_grants := [g | some g in grant_rows; grant_row_readable(g)]

# --- the grant row's own scope facts ------------------------------------------------

# The minimality the gate models: an allowed action set is a set of
# exact names. A wildcard is a grant that can do anything; a
# metacharacter is a wildcard wearing a beard — both refused, on
# either reading of "broad".
grant_action_wildcard(g) if {
	some a in grant_action_rows(g)
	a == "*"
}

grant_action_glob(g) if {
	some a in grant_action_rows(g)
	not a == "*"
	regex.match(`[*?[{]`, a)
}

grant_action_duplicate(g) if {
	some a in grant_action_rows(g)
	count([x | some x in grant_action_rows(g); x == a]) > 1
}

# The grant's own action set is readable when the actions field is an
# array — malformed rows are findings, and the join judges the
# well-formed subset.
grant_actions_readable(g) if {
	is_object(g)
	is_array(object.get(g, "actions", null))
}

# An expired grant: the expiry is a real date, and today is past it.
# The anchor date is injected; the comparison is arithmetic, never a
# time builtin.
grant_expired(g) if {
	lib.is_valid_date(grant_expires(g))
	lib.is_valid_date(today_date)
	lib.date_to_days(grant_expires(g)) < lib.date_to_days(today_date)
}

# --- the package manifest: the fields the join reads -------------------------------

# The broker gate composes on the component package conformance
# validator (#101): the package's own conformance — its registry
# admission, its signature, its attestation — is that gate's word.
# This gate reads only what the grant join needs: the component's
# name, the artifact digest it publishes, and the dependencies it
# pins by digest.
package_component := object.get(package_doc, "component", null)

package_digest := object.get(package_doc, "artifactDigest", null)

# The package's pinned dependencies. Absent, the package pins none
# — the join then resolves grants against the package's own entry
# alone, honestly.
dependencies_present if {
	is_object(package_doc)
	object.get(package_doc, "dependencies", null) != null
}

dependency_rows := [d | some d in as_array(package_doc, "dependencies"); is_object(d)]

dep_package(d) := object.get(d, "package", null)

dep_digest(d) := object.get(d, "digest", null)

# A dependency row the join can trust: a named package pinned at a
# real sha256 digest. Shape quality beyond this is the component
# gate's finding (#101), never an ambiguity for lookups.
dep_row_well_formed(d) if {
	is_object(d)
	lib.is_nonempty_string(dep_package(d))
	is_artifact_digest(dep_digest(d))
}

# The well-formed pinned dependencies, in document order.
declared_dependencies := [d | some d in dependency_rows; dep_row_well_formed(d)]

# The package dependencies are readable when the field is absent (the
# package pins none) or an array — malformed rows are findings, and
# the join judges the well-formed subset.
package_dependencies_readable if {
	not dependencies_present
}

package_dependencies_readable if {
	is_object(package_doc)
	is_array(object.get(package_doc, "dependencies", null))
}

# --- the join: the manifest resolutions of a component name ------------------------

# A component the manifest vouches for: the package itself (its name
# and published artifact digest) or one of its pinned dependencies
# (the name and the pinned digest). Only readable entries resolve;
# the malformed rows have their own findings.
component_resolutions(component) := digests if {
	digests := {digest |
		lib.is_nonempty_string(package_component)
		component == package_component
		is_artifact_digest(package_digest)
		digest := package_digest
	} | {dep_digest(d) |
		some d in declared_dependencies
		dep_package(d) == component
	}
}

# The component named by a grant resolves when the manifest carries
# it at least once; the grant drifts when its pinned digest is none
# of the resolutions. Both are join questions, judged here.
component_resolves(component) if {
	lib.is_nonempty_string(component)
	count(component_resolutions(component)) > 0
}

grant_digest_drifts(g) if {
	lib.is_nonempty_string(grant_component(g))
	component_resolves(grant_component(g))
	is_artifact_digest(grant_digest(g))
	not grant_digest(g) in component_resolutions(grant_component(g))
}

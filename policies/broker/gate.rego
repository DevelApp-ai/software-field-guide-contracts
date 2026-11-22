# Supply-chain IAM-broker scope gate — The Software Field Guide,
# issue #104.
#
# The IAM broker is the chokepoint for component consumption: every
# grant names one principal, one component, an allowed action set,
# and an expiry — and the broker's value collapses if scopes are
# broad or grants are invisible. This gate joins the broker grant
# document (the broker's word — the declared consumer identities and
# every grant it issued, each pinning its component by sha256 digest)
# against the component package manifest (the package's word — the
# component it packages, the artifact digest it publishes, and the
# dependencies it pins by digest) and refuses — a conformance gate,
# not an advisor: a grant for a component the manifest never named
# is a claim nobody can check, and a grant pinning a different
# digest is a grant for bytes the package never published. The two
# drifts the gate knows by name: a grant whose component the
# manifest does not resolve (gate/component-unresolved) and a grant
# pinned at a digest the manifest never published for that component
# (gate/digest-drift). What also fails the gate is a document the
# gate cannot read — a grant document or manifest with broken stamps
# or shapes is a question the gate refuses to answer on its own
# inputs. The verdict ladder separates the failures honestly:
# unreadable (a document is malformed), drifts (only join drifts),
# consistent. The gate composes on the component package conformance
# validator (#101): the package's own conformance is that gate's
# word; this gate reads only what the grant join needs.
#
# Input (JSON): {"broker": {...}, "package": {...},
#                "today": "YYYY-MM-DD", "brokerFile": "...",
#                "packageFile": "..."}
# Result:       {"valid": bool, "findings": [...], "grants": [...], "verdict": "..."}
package broker

import rego.v1

import data.broker.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"grants": grant_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := (validate_findings | package_findings) | join_findings

# --- findings: the package manifest at the gate --------------------------------

# The join cannot run without the package's word: the component it
# packages, the artifact digest it publishes, and the dependencies it
# pins by digest. The package's own conformance — registry
# admission, signature, attestation — is the component gate's word
# (#101); this gate requires only what the grant join reads, and
# says so.
package_identity_findings := ((p_package_missing | p_component_required) | p_digest_required) | p_digest_malformed

package_dependency_findings := (((p_dependencies_must_be_array | p_dependency_must_be_object) | p_dependency_package_required) | p_dependency_digest_required) | p_dependency_digest_malformed

package_findings := package_identity_findings | package_dependency_findings

p_package_missing contains finding if {
	not is_object(package_doc)
	finding := {
		"severity": "error",
		"rule": "package/missing",
		"message": sprintf("the component package manifest is required at the gate: pass it as input.package — the grants are vouched for against the package's own word (%s)", [package_file]),
		"path": "$.package",
	}
}

p_component_required contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(package_component)
	finding := {
		"severity": "error",
		"rule": "component/name-required",
		"message": sprintf("the package manifest must name the component it packages: grants are resolved against the package's own name and the names it pins (%s)", [package_file]),
		"path": "$.package.component",
	}
}

p_digest_required contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(package_digest)
	finding := {
		"severity": "error",
		"rule": "artifact/digest-required",
		"message": sprintf("the package manifest must publish an artifactDigest: grants on the package are vouched against it — a package without a digest is a name, not an artifact (%s)", [package_file]),
		"path": "$.package.artifactDigest",
	}
}

p_digest_malformed contains finding if {
	is_object(package_doc)
	lib.is_nonempty_string(package_digest)
	not is_artifact_digest(package_digest)
	finding := {
		"severity": "error",
		"rule": "artifact/digest-malformed",
		"message": sprintf("the artifactDigest must be a sha256 digest (64 lowercase hex characters) — '%v' is not a digest the gate agreed to read (%s)", [package_digest, package_file]),
		"path": "$.package.artifactDigest",
	}
}

# The pinned dependencies, when the package declares any: an array
# of {package, digest} rows. Absent is honest — the package pins
# none — but a present-and-malformed field is a document the gate
# cannot read.
p_dependencies_must_be_array contains finding if {
	is_object(package_doc)
	dependencies_present
	not is_array(object.get(package_doc, "dependencies", null))
	finding := {
		"severity": "error",
		"rule": "package/dependencies-must-be-array",
		"message": sprintf("the package manifest's dependencies must be an array of {package, digest} rows: the names and digests the grants resolve against (%s)", [package_file]),
		"path": "$.package.dependencies",
	}
}

p_dependency_must_be_object contains finding if {
	some d in as_array(package_doc, "dependencies")
	not is_object(d)
	finding := {
		"severity": "error",
		"rule": "package/dependency-must-be-object",
		"message": sprintf("every pinned dependency must be an object: {package, digest} (%s)", [package_file]),
		"path": "$.package.dependencies",
	}
}

p_dependency_package_required contains finding if {
	some d in dependency_rows
	not lib.is_nonempty_string(dep_package(d))
	finding := {
		"severity": "error",
		"rule": "package/dependency-package-required",
		"message": sprintf("every pinned dependency must name the package it pins: a dependency pinned to no name cannot be resolved against a grant (%s)", [package_file]),
		"path": "$.package.dependencies",
	}
}

p_dependency_digest_required contains finding if {
	some d in dependency_rows
	not lib.is_nonempty_string(dep_digest(d))
	finding := {
		"severity": "error",
		"rule": "package/dependency-digest-required",
		"message": sprintf("every pinned dependency must pin a digest: a dependency pinned by name alone is a dependency that can change under the package (%s)", [package_file]),
		"path": "$.package.dependencies",
	}
}

p_dependency_digest_malformed contains finding if {
	some d in dependency_rows
	lib.is_nonempty_string(dep_digest(d))
	not is_artifact_digest(dep_digest(d))
	finding := {
		"severity": "error",
		"rule": "package/dependency-digest-malformed",
		"message": sprintf("the pinned dependency digest must be a sha256 digest (64 lowercase hex characters) — '%v' is not a digest the gate agreed to read (%s)", [dep_digest(d), package_file]),
		"path": "$.package.dependencies",
	}
}

# --- the two drifts, named ------------------------------------------------------

join_findings := j_component_unresolved | j_digest_drift

# (1) The unresolved grant: the grant names a component the
# manifest cannot vouch for — neither the package it packages nor
# one of the dependencies it pins. A grant for a component nobody
# packaged is a claim nobody can check.
j_component_unresolved contains finding if {
	is_object(broker_doc)
	is_object(package_doc)
	some i, g in grant_rows
	grant_row_readable(g)
	lib.is_nonempty_string(package_component)
	not component_resolves(grant_component(g))
	finding := {
		"severity": "error",
		"rule": "gate/component-unresolved",
		"message": sprintf("the grant of '%s' on '%s' names a component the package manifest neither packages nor pins: a grant for a component nobody packaged is a claim nobody can check (%s, %s)", [grant_principal(g), grant_component(g), broker_file, package_file]),
		"path": sprintf("$.broker.grants[%d].component", [i]),
	}
}

# (2) The digest drift: the grant resolves to a manifest entry but
# pins a digest the manifest never published for that component — a
# grant for bytes the package never shipped.
j_digest_drift contains finding if {
	is_object(broker_doc)
	is_object(package_doc)
	some i, g in grant_rows
	grant_row_readable(g)
	grant_digest_drifts(g)
	finding := {
		"severity": "error",
		"rule": "gate/digest-drift",
		"message": sprintf("the grant of '%s' on '%s' pins the digest %v, but the package manifest carries the component at %v: the grant is for bytes the package never published (%s, %s)", [grant_principal(g), grant_component(g), grant_digest(g), concat(", ", sort([d | some d in component_resolutions(grant_component(g))])), broker_file, package_file]),
		"path": sprintf("$.broker.grants[%d].digest", [i]),
	}
}

# --- the grant cards: the verdict the playground renders ---------------------------

# The board: one card per declared grant — its component resolved by
# the manifest at exactly the pinned digest, for a declared
# principal, with an exact action set and the clock still on it
# (consistent), or the first divergence named. The cards render only
# when the join can be asked: both documents readable, the
# principals and grants countable, the package's own entry
# readable. A grant row too broken to name its principal and its
# component is a finding, never an ambiguous card.
grant_cards := [card |
	some g in readable_grants
	card := grant_card(g)
] if cards_renderable

grant_cards := [] if not cards_renderable

cards_renderable if {
	is_object(broker_doc)
	is_array(object.get(broker_doc, "principals", null))
	is_array(object.get(broker_doc, "grants", null))
	is_object(package_doc)
	lib.is_nonempty_string(package_component)
	is_artifact_digest(package_digest)
	package_dependencies_readable
}

grant_card(g) := {
	"principal": grant_principal(g),
	"component": grant_component(g),
	"verdict": grant_card_verdict(g),
	"detail": grant_card_detail(g),
}

grant_card_verdict(g) := "drifts" if grant_card_drifts(g)

grant_card_verdict(g) := "consistent" if not grant_card_drifts(g)

# The card drifts when the join drifts or the grant's own scope is
# not clean; the detail names the first divergence, in a fixed
# order: the join first (the component unresolved, then the digest
# drift), then the named identity, then the action set, then the
# clock.
grant_card_drifts(g) if {
	not component_resolves(grant_component(g))
}

grant_card_drifts(g) if {
	component_resolves(grant_component(g))
	grant_digest_drifts(g)
}

grant_card_drifts(g) if {
	not principal_declared(grant_principal(g))
}

grant_card_drifts(g) if {
	not grant_actions_readable(g)
}

grant_card_drifts(g) if {
	grant_actions_readable(g)
	count(grant_action_rows(g)) == 0
}

grant_card_drifts(g) if {
	unnamed_grant_action(g)
}

grant_card_drifts(g) if {
	grant_action_wildcard(g)
}

grant_card_drifts(g) if {
	grant_action_glob(g)
}

grant_card_drifts(g) if {
	grant_action_duplicate(g)
}

grant_card_drifts(g) if {
	not lib.is_valid_date(grant_expires(g))
}

grant_card_drifts(g) if {
	lib.is_valid_date(grant_expires(g))
	grant_expired(g)
}

# The details, ordered: each guard mirrors the drift that resolved
# it, deterministically.
grant_card_detail(g) := sprintf("names the component '%s', which the package manifest neither packages nor pins (%s, %s)", [grant_component(g), broker_file, package_file]) if {
	not component_resolves(grant_component(g))
}

grant_card_detail(g) := sprintf("pins the digest %v, but the package manifest carries '%s' at %v (%s, %s)", [grant_digest(g), grant_component(g), concat(", ", sort([d | some d in component_resolutions(grant_component(g))])), broker_file, package_file]) if {
	component_resolves(grant_component(g))
	grant_digest_drifts(g)
}

grant_card_detail(g) := sprintf("names the principal '%s', which the broker never declared (%s)", [grant_principal(g), broker_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	not principal_declared(grant_principal(g))
}

grant_card_detail(g) := sprintf("carries an actions field that is not an array (%s)", [broker_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	principal_declared(grant_principal(g))
	not grant_actions_readable(g)
}

grant_card_detail(g) := sprintf("allows no action at all (%s)", [broker_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	principal_declared(grant_principal(g))
	grant_actions_readable(g)
	count(grant_action_rows(g)) == 0
}

grant_card_detail(g) := sprintf("carries an action that is not a non-empty name (%s)", [broker_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	principal_declared(grant_principal(g))
	grant_actions_readable(g)
	count(grant_action_rows(g)) > 0
	unnamed_grant_action(g)
}

grant_card_detail(g) := sprintf("allows the wildcard action: a grant that can do anything is the scope the broker exists to prevent (%s)", [broker_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	principal_declared(grant_principal(g))
	grant_actions_readable(g)
	count(grant_action_rows(g)) > 0
	not unnamed_grant_action(g)
	grant_action_wildcard(g)
}

grant_card_detail(g) := sprintf("allows the action '%s', which carries glob metacharacters the gate refuses to guess against (%s)", [grant_action_globs(g), broker_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	principal_declared(grant_principal(g))
	grant_actions_readable(g)
	count(grant_action_rows(g)) > 0
	not unnamed_grant_action(g)
	not grant_action_wildcard(g)
	grant_action_glob(g)
}

grant_card_detail(g) := sprintf("lists the action '%s' more than once: an action set is a set (%s)", [grant_duplicate_actions(g), broker_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	principal_declared(grant_principal(g))
	grant_actions_readable(g)
	count(grant_action_rows(g)) > 0
	not unnamed_grant_action(g)
	not grant_action_wildcard(g)
	not grant_action_glob(g)
	grant_action_duplicate(g)
}

grant_card_detail(g) := sprintf("carries an expiry that is not a real calendar date (%s)", [broker_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	principal_declared(grant_principal(g))
	grant_actions_readable(g)
	count(grant_action_rows(g)) > 0
	not unnamed_grant_action(g)
	not grant_action_wildcard(g)
	not grant_action_glob(g)
	not grant_action_duplicate(g)
	not lib.is_valid_date(grant_expires(g))
}

grant_card_detail(g) := sprintf("expired on %s, before today: an expired grant still on the books is a grant the broker never revoked (%s)", [grant_expires(g), broker_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	principal_declared(grant_principal(g))
	grant_actions_readable(g)
	count(grant_action_rows(g)) > 0
	not unnamed_grant_action(g)
	not grant_action_wildcard(g)
	not grant_action_glob(g)
	not grant_action_duplicate(g)
	lib.is_valid_date(grant_expires(g))
	grant_expired(g)
}

grant_card_detail(g) := sprintf("vouched by the manifest at the pinned digest, %d allowed action(s) until %s (%s, %s)", [count(grant_action_rows(g)), grant_expires(g), broker_file, package_file]) if {
	component_resolves(grant_component(g))
	not grant_digest_drifts(g)
	principal_declared(grant_principal(g))
	grant_actions_readable(g)
	count(grant_action_rows(g)) > 0
	not unnamed_grant_action(g)
	not grant_action_wildcard(g)
	not grant_action_glob(g)
	not grant_action_duplicate(g)
	lib.is_valid_date(grant_expires(g))
	not grant_expired(g)
}

# An action name that is not a non-empty name, cited
# deterministically.
unnamed_grant_action(g) if {
	some a in as_array(g, "actions")
	not lib.is_nonempty_string(a)
}

# --- the verdict ladder ------------------------------------------------------------

# The conformance ladder, honest about what each rung means: a
# document the gate cannot read is a question the gate refuses to
# answer; drifts are consistency failures the broker must fix
# before the grants are believed; a grant document whose every
# grant the manifest vouches for, for declared principals, with
# exact action sets and the clocks still on, is consistent.
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

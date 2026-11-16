# Component package conformance gate — The Software Field Guide,
# issue #101.
#
# The package manifest declares the package; the registry holds the
# estate's word — the packages it admitted, each as a component,
# version, tier, and digest row. This gate joins the two documents
# and refuses — a conformance gate, not an advisor: a package that
# is not in conformance does not ship. The five drifts the gate
# knows by name: an unregistered package (no registry row for its
# component+version), an artifact that drifted from its
# registration (the artifact digest no longer equals the registry's
# digest for that version), an unresolved dependency (the registry
# never admitted the package it names), a stale pin (the registry
# carries the package but not at the pinned digest), and a tier
# violated downward (a customer-tier package depending on a
# project-tier one). What also fails the gate is a document the
# gate cannot read — a package or registry with broken stamps or
# shapes is a question the gate refuses to answer on its own
# inputs. The verdict ladder separates the two honestly:
# unreadable (a document is malformed), drifts (only join drifts),
# consistent. The cards render the whole board: one row for the
# package's registration, one per dependency.
#
# Input (JSON): {"package": {...}, "registry": {...},
#                "today": "YYYY-MM-DD", "packageFile": "...",
#                "registryFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package component

import rego.v1

import data.component.lib

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

gate_findings := ((((((((validate_findings | g_registry_missing) | g_registry_stamps) | g_registry_shape) | g_registry_rows) | g_package_unregistered) | g_package_digest_drift) | g_dependency_unresolved) | g_dependency_digest_mismatch) | g_dependency_hierarchy_violation

# --- findings: the registry document at the gate -------------------------------

g_registry_missing contains finding if {
	not is_object(registry_doc)
	finding := {
		"severity": "error",
		"rule": "registry/missing",
		"message": "the component registry is required at the gate: pass it as input.registry — admission is the registry's word, not the package's",
		"path": "$.registry",
	}
}

g_registry_stamps contains finding if {
	is_object(registry_doc)
	not is_positive_integer(object.get(registry_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "registry/version-required",
		"message": sprintf("the component registry must carry a version (a positive integer): admission records are versioned like the estate that keeps them (%s)", [registry_file]),
		"path": "$.registry.version",
	}
}

g_registry_stamps contains finding if {
	is_object(registry_doc)
	not lib.is_valid_date(object.get(registry_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "registry/reviewed-on-invalid",
		"message": sprintf("the component registry must carry reviewedOn as a real YYYY-MM-DD date (%s)", [registry_file]),
		"path": "$.registry.reviewedOn",
	}
}

g_registry_stamps contains finding if {
	is_object(registry_doc)
	lib.is_valid_date(object.get(registry_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(registry_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "registry/reviewed-in-future",
		"message": sprintf("the component registry carries a reviewedOn date in the future (%s)", [registry_file]),
		"path": "$.registry.reviewedOn",
	}
}

g_registry_stamps contains finding if {
	is_object(registry_doc)
	lib.is_valid_date(object.get(registry_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(registry_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "registry/reviewed-stale",
		"message": sprintf("the component registry was reviewed more than 365 days before today: a registry nobody reviews is an estate nobody admits to (%s)", [registry_file]),
		"path": "$.registry.reviewedOn",
	}
}

g_registry_stamps contains finding if {
	is_object(registry_doc)
	not lib.is_nonempty_string(object.get(registry_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "registry/owner-required",
		"message": sprintf("the component registry must name an owner: admission records without an owner are records nobody maintains (%s)", [registry_file]),
		"path": "$.registry.owner",
	}
}

# --- findings: the registry's admitted packages ---------------------------------

g_registry_shape contains finding if {
	is_object(registry_doc)
	not is_array(object.get(registry_doc, "packages", null))
	finding := {
		"severity": "error",
		"rule": "registry/packages-must-be-array",
		"message": sprintf("the component registry's packages must be an array of {component, version, hierarchy, digest} rows (%s)", [registry_file]),
		"path": "$.registry.packages",
	}
}

g_registry_shape contains finding if {
	is_object(registry_doc)
	is_array(object.get(registry_doc, "packages", null))
	some r in object.get(registry_doc, "packages", [])
	not is_object(r)
	finding := {
		"severity": "error",
		"rule": "registry/row-must-be-object",
		"message": sprintf("every registry row must be an object: {component, version, hierarchy, digest} (%s)", [registry_file]),
		"path": "$.registry.packages",
	}
}

g_registry_rows contains finding if {
	some r in registry_rows
	not lib.is_nonempty_string(row_component(r))
	finding := {
		"severity": "error",
		"rule": "registry/row-name-required",
		"message": sprintf("every registry row must name the component it admits (%s)", [registry_file]),
		"path": "$.registry.packages",
	}
}

g_registry_rows contains finding if {
	some r in registry_rows
	not lib.is_nonempty_string(row_version(r))
	finding := {
		"severity": "error",
		"rule": "registry/row-version-required",
		"message": sprintf("every registry row must carry the version it admits: admission is per component+version (%s)", [registry_file]),
		"path": "$.registry.packages",
	}
}

g_registry_rows contains finding if {
	some r in registry_rows
	lib.is_nonempty_string(row_hierarchy(r))
	not hierarchy_known(row_hierarchy(r))
	finding := {
		"severity": "error",
		"rule": "registry/row-hierarchy-unknown",
		"message": sprintf("a registry row declares the tier '%v', which the validator never agreed to model: general, customer, or project (%s)", [row_hierarchy(r), registry_file]),
		"path": "$.registry.packages",
	}
}

g_registry_rows contains finding if {
	some r in registry_rows
	lib.is_nonempty_string(row_digest(r))
	not is_artifact_digest(row_digest(r))
	finding := {
		"severity": "error",
		"rule": "registry/row-digest-malformed",
		"message": sprintf("a registry digest must be a sha256 digest (64 lowercase hex characters) — '%v' is not a digest the gate agreed to read (%s)", [row_digest(r), registry_file]),
		"path": "$.registry.packages",
	}
}

g_registry_rows contains finding if {
	some r in registry_rows
	lib.is_nonempty_string(row_component(r))
	lib.is_nonempty_string(row_version(r))
	count([x | some x in registry_rows; row_component(x) == row_component(r); row_version(x) == row_version(r)]) > 1
	finding := {
		"severity": "error",
		"rule": "registry/row-duplicate",
		"message": sprintf("the registry admits '%v' v%v more than once: one admission per component+version (%s)", [row_component(r), row_version(r), registry_file]),
		"path": "$.registry.packages",
	}
}

# --- the five drifts, named -----------------------------------------------------

# (1) The unregistered package: the manifest names a component and
# version the registry never admitted. A package the estate never
# admitted is a package the estate never vouched for.
g_package_unregistered contains finding if {
	is_object(package_doc)
	lib.is_nonempty_string(package_name)
	lib.is_nonempty_string(package_version)
	not row_registered(package_name, package_version)
	finding := {
		"severity": "error",
		"rule": "gate/package-unregistered",
		"message": sprintf("the package '%v' v%v is not registered: the registry never admitted it (%s, %s)", [package_name, package_version, package_file, registry_file]),
		"path": "$.package",
	}
}

# (2) The artifact that drifted from its registration: the registry
# admitted the package, but the artifact digest it publishes today
# is not the digest the registry recorded at admission. Either the
# registration is stale or the artifact was swapped — both are
# drift, and the gate refuses both.
g_package_digest_drift contains finding if {
	is_object(package_doc)
	lib.is_nonempty_string(package_name)
	lib.is_nonempty_string(package_version)
	row := row_for(package_name, package_version)
	is_artifact_digest(object.get(package_doc, "artifactDigest", null))
	is_artifact_digest(row_digest(row))
	object.get(package_doc, "artifactDigest", null) != row_digest(row)
	finding := {
		"severity": "error",
		"rule": "gate/package-digest-drift",
		"message": sprintf("the artifact digest does not match the registry's digest for '%v' v%v: the package drifted after registration, or the registration is stale (%s, %s)", [package_name, package_version, package_file, registry_file]),
		"path": "$.package.artifactDigest",
	}
}

# (3) The unresolved dependency: the manifest pins a package the
# registry never admitted under any version. Depending on the
# unadmitted is building on the estate's blind side.
g_dependency_unresolved contains finding if {
	some d in dependencies
	lib.is_nonempty_string(dependency_name(d))
	not dependency_resolved(dependency_name(d))
	finding := {
		"severity": "error",
		"rule": "gate/dependency-unresolved",
		"message": sprintf("the dependency '%v' resolves to no package in the registry: the estate never admitted what this package builds on (%s, %s)", [dependency_name(d), package_file, registry_file]),
		"path": "$.package.dependencies",
	}
}

# (4) The stale pin: the registry carries the package, but not at
# the digest the manifest pins. A pin that does not match the
# registry's record is a pin to something the estate never admitted.
g_dependency_digest_mismatch contains finding if {
	some d in dependencies
	lib.is_nonempty_string(dependency_name(d))
	is_artifact_digest(dependency_digest(d))
	dependency_resolved(dependency_name(d))
	not dependency_pinned(dependency_name(d), dependency_digest(d))
	finding := {
		"severity": "error",
		"rule": "gate/dependency-digest-mismatch",
		"message": sprintf("the pin on '%v' matches no digest the registry records for it: the pin is stale, or the registry moved (%s, %s)", [dependency_name(d), package_file, registry_file]),
		"path": "$.package.dependencies",
	}
}

# (5) The tier violated downward: a customer-tier package depends
# on a package the registry registers as project-tier. The tier is
# a promise about reuse; depending downward is a package pretending
# to be more reusable than it is.
g_dependency_hierarchy_violation contains finding if {
	some d in dependencies
	lib.is_nonempty_string(dependency_name(d))
	package_hierarchy == "customer"
	some r in registry_rows
	row_component(r) == dependency_name(d)
	row_hierarchy(r) == "project"
	finding := {
		"severity": "error",
		"rule": "gate/dependency-hierarchy-violation",
		"message": sprintf("the customer-tier package depends on '%v', which the registry registers as project-tier: the tiers are one-way, and this dependency points down (%s, %s)", [dependency_name(d), package_file, registry_file]),
		"path": "$.package.dependencies",
	}
}

# --- the cards -----------------------------------------------------------------

# The board: one row for the package's registration, one per
# dependency. Only well-formed rows render; a malformed row is a
# finding, not a card.
advice_cards := array.concat(package_cards, dependency_cards)

# The package's registration: registered at the digest it
# publishes, registered but drifted, or not registered at all.
package_cards := [card | card := package_card]

package_card := card if {
	is_object(package_doc)
	lib.is_nonempty_string(package_name)
	lib.is_nonempty_string(package_version)
	card := {
		"area": "package",
		"item": package_name,
		"verdict": package_card_verdict,
		"detail": package_card_detail,
	}
}

package_card_verdict := "consistent" if {
	row_registered(package_name, package_version)
	row := row_for(package_name, package_version)
	is_artifact_digest(row_digest(row))
	is_artifact_digest(object.get(package_doc, "artifactDigest", null))
	object.get(package_doc, "artifactDigest", null) == row_digest(row)
}

package_card_verdict := "drifts" if not package_card_consistent

package_card_consistent if {
	row_registered(package_name, package_version)
	row := row_for(package_name, package_version)
	is_artifact_digest(row_digest(row))
	is_artifact_digest(object.get(package_doc, "artifactDigest", null))
	object.get(package_doc, "artifactDigest", null) == row_digest(row)
}

package_card_detail := sprintf("v%v registered, publishing the digest the registry recorded (%s, %s)", [package_version, package_file, registry_file]) if {
	package_card_consistent
}

package_card_detail := sprintf("v%v is not registered: a package the estate never admitted (%s, %s)", [package_version, package_file, registry_file]) if {
	not row_registered(package_name, package_version)
}

package_card_detail := sprintf("v%v registered, but the artifact digest drifted from the registry's record (%s, %s)", [package_version, package_file, registry_file]) if {
	row_registered(package_name, package_version)
	not package_card_consistent
}

# The dependencies: each resolved to the tier the registry declares,
# pinned to a digest the registry records, and pointed only
# sideways or up.
dependency_cards := sort([card |
	some d in dependencies
	lib.is_nonempty_string(dependency_name(d))
	card := {
		"area": "dependencies",
		"item": dependency_name(d),
		"verdict": dependency_card_verdict(d),
		"detail": dependency_card_detail(d),
	}
])

dependency_card_verdict(d) := "consistent" if {
	dependency_pinned(dependency_name(d), dependency_digest(d))
	not dependency_points_down(d)
}

dependency_card_verdict(d) := "drifts" if not dependency_card_consistent(d)

dependency_card_consistent(d) if {
	dependency_pinned(dependency_name(d), dependency_digest(d))
	not dependency_points_down(d)
}

dependency_points_down(d) if {
	package_hierarchy == "customer"
	some r in registry_rows
	row_component(r) == dependency_name(d)
	row_hierarchy(r) == "project"
}

dependency_card_detail(d) := sprintf("pinned to a digest the registry records for '%v' (%s, %s)", [dependency_name(d), package_file, registry_file]) if {
	dependency_card_consistent(d)
}

dependency_card_detail(d) := sprintf("resolves to no package in the registry (%s, %s)", [package_file, registry_file]) if {
	not dependency_resolved(dependency_name(d))
}

dependency_card_detail(d) := sprintf("the pin matches no digest the registry records for '%v': stale pin, or the registry moved (%s, %s)", [dependency_name(d), package_file, registry_file]) if {
	dependency_resolved(dependency_name(d))
	not dependency_pinned(dependency_name(d), dependency_digest(d))
}

dependency_card_detail(d) := sprintf("the registry registers '%v' as project-tier, below this customer-tier package (%s, %s)", [dependency_name(d), package_file, registry_file]) if {
	dependency_pinned(dependency_name(d), dependency_digest(d))
	dependency_points_down(d)
}

# --- the verdict ladder -----------------------------------------------------------

# The conformance ladder, honest about what each rung means: a
# document the gate cannot read is a question the gate refuses to
# answer; drifts are conformance failures the package must fix
# before it ships; a package registered at its published digest
# with its pins answered for is consistent.
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

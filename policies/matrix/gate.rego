# Render-matrix consistency gate — The Software Field Guide, issue
# #102.
#
# One component rendered across many fabrics drifts silently: one
# fabric runs a different version, a digest mismatch appears after a
# re-render, a policy binding exists in one fabric only, a fabric in
# the matrix has no render at all. This gate joins the render matrix
# (the fabrics' answer — each fabric's rendered copy of the package)
# against the component package manifest (the package's word — the
# version, the artifact digest, and the policy bindings it declares)
# and refuses — a conformance gate, not an advisor: a render matrix
# that disagrees with the manifest is a fabric running something the
# package never published. The six drifts the gate knows by name: a
# matrix for a different component (gate/component-mismatch), a
# fabric with no render at all (gate/fabric-unrendered), a fabric
# rendering a different version (gate/render-version-skew), a fabric
# that re-rendered to a different digest (gate/render-digest-drift),
# a declared policy binding missing from a fabric
# (gate/binding-missing), and a fabric holding a binding the package
# never declared (gate/binding-undeclared). What also fails the gate
# is a document the gate cannot read — a matrix or manifest with
# broken stamps or shapes is a question the gate refuses to answer
# on its own inputs. The verdict ladder separates the two honestly:
# unreadable (a document is malformed), drifts (only join drifts),
# consistent. The gate composes on the component package conformance
# validator (#101): the package's own conformance is that gate's
# word; this gate reads only what the render join needs.
#
# Input (JSON): {"package": {...}, "matrix": {...},
#                "today": "YYYY-MM-DD", "packageFile": "...",
#                "matrixFile": "..."}
# Result:       {"valid": bool, "findings": [...], "fabrics": [...], "verdict": "..."}
package matrix

import rego.v1

import data.matrix.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"fabrics": fabric_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := (validate_findings | package_findings) | join_findings

# --- findings: the package manifest at the gate --------------------------------

# The join cannot run without the package's word: the component's
# name, the version every fabric must render, and the artifact
# digest every fabric must have rendered. The package's own
# conformance — registry admission, signature, attestation — is the
# component gate's word (#101); this gate requires only what the
# render join reads, and says so.
package_findings := ((((((((p_package_missing | p_component_required) | p_version_required) | p_digest_required) | p_digest_malformed) | p_bindings_must_be_array) | p_binding_must_be_object) | p_binding_policy_required) | p_binding_path_required) | p_binding_duplicate

p_package_missing contains finding if {
	not is_object(package_doc)
	finding := {
		"severity": "error",
		"rule": "package/missing",
		"message": sprintf("the component package manifest is required at the gate: pass it as input.package — the fabrics' renders are judged against the package's own word (%s)", [package_file]),
		"path": "$.package",
	}
}

p_component_required contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(package_component)
	finding := {
		"severity": "error",
		"rule": "component/name-required",
		"message": sprintf("the package manifest must name the component it packages: the render matrix is joined to the package by name (%s)", [package_file]),
		"path": "$.package.component",
	}
}

p_version_required contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(package_version)
	finding := {
		"severity": "error",
		"rule": "package/version-required",
		"message": sprintf("the package manifest must carry a version string: the fabrics' rendered versions are judged against it (%s)", [package_file]),
		"path": "$.package.version",
	}
}

p_digest_required contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(package_digest)
	finding := {
		"severity": "error",
		"rule": "artifact/digest-required",
		"message": sprintf("the package manifest must publish an artifactDigest: the fabrics' rendered digests are judged against it — a package without a digest is a name, not an artifact (%s)", [package_file]),
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

# The declared policy bindings, when the package declares any: an
# array of {policy, path} rows. Absent is honest — the package
# declares none — but a present-and-malformed field is a document
# the gate cannot read.
p_bindings_must_be_array contains finding if {
	is_object(package_doc)
	object.get(package_doc, "policyBindings", null) != null
	not is_array(object.get(package_doc, "policyBindings", null))
	finding := {
		"severity": "error",
		"rule": "package/bindings-must-be-array",
		"message": sprintf("the package manifest's policyBindings must be an array of {policy, path} rows: the bindings every fabric must hold in force (%s)", [package_file]),
		"path": "$.package.policyBindings",
	}
}

p_binding_must_be_object contains finding if {
	some b in as_array(package_doc, "policyBindings")
	not is_object(b)
	finding := {
		"severity": "error",
		"rule": "package/binding-must-be-object",
		"message": sprintf("every declared policy binding must be an object: {policy, path} (%s)", [package_file]),
		"path": "$.package.policyBindings",
	}
}

p_binding_policy_required contains finding if {
	some b in package_bindings
	not lib.is_nonempty_string(binding_policy(b))
	finding := {
		"severity": "error",
		"rule": "package/binding-policy-required",
		"message": sprintf("every declared policy binding must name the policy it binds (%s)", [package_file]),
		"path": "$.package.policyBindings",
	}
}

p_binding_path_required contains finding if {
	some b in package_bindings
	not lib.is_nonempty_string(binding_path(b))
	finding := {
		"severity": "error",
		"rule": "package/binding-path-required",
		"message": sprintf("every declared policy binding must name the exact path it renders from: a binding pinned to no path is a binding that can point anywhere (%s)", [package_file]),
		"path": "$.package.policyBindings",
	}
}

p_binding_duplicate contains finding if {
	some b in declared_bindings
	count([d |
		some d in declared_bindings
		binding_policy(d) == binding_policy(b)
	]) > 1
	finding := {
		"severity": "error",
		"rule": "package/binding-duplicate",
		"message": sprintf("the policy '%v' is declared more than once: one policy, one binding — a policy bound twice is a binding nobody can diff (%s)", [binding_policy(b), package_file]),
		"path": "$.package.policyBindings",
	}
}

# --- the six drifts, named ------------------------------------------------------

join_findings := ((((j_component_mismatch | j_fabric_unrendered) | j_render_version_skew) | j_render_digest_drift) | j_binding_missing) | j_binding_undeclared

# (1) The mismatched join: the matrix renders a component the
# manifest never packaged. The join cannot even be asked.
j_component_mismatch contains finding if {
	is_object(matrix_doc)
	is_object(package_doc)
	lib.is_nonempty_string(matrix_component)
	lib.is_nonempty_string(package_component)
	matrix_component != package_component
	finding := {
		"severity": "error",
		"rule": "gate/component-mismatch",
		"message": sprintf("the render matrix is for '%v', but the package manifest packages '%v': the renders are being judged against somebody else's package (%s, %s)", [matrix_component, package_component, matrix_file, package_file]),
		"path": "$.matrix.component",
	}
}

# (2) The fabric with no render at all: the matrix declares a
# fabric and nothing rendered onto it — coverage claimed, never
# delivered.
j_fabric_unrendered contains finding if {
	some fabric in declared_fabrics
	not fabric_rendered(fabric)
	finding := {
		"severity": "error",
		"rule": "gate/fabric-unrendered",
		"message": sprintf("fabric '%v' is declared in the matrix but has no render row: a fabric with no render is coverage claimed and never delivered (%s)", [fabric, matrix_file]),
		"path": "$.matrix.fabrics",
	}
}

# (3) The version skew: a fabric rendering a different version of
# the package — one fabric quietly running yesterday's package.
j_render_version_skew contains finding if {
	some i, x in render_rows
	render_row_well_formed(x)
	fabric_declared(render_fabric(x))
	lib.is_nonempty_string(package_version)
	render_version(x) != package_version
	finding := {
		"severity": "error",
		"rule": "gate/render-version-skew",
		"message": sprintf("fabric '%v' renders '%v' v%v, but the package manifest publishes v%v: one fabric is quietly running a different release (%s, %s)", [render_fabric(x), package_component, render_version(x), package_version, matrix_file, package_file]),
		"path": sprintf("$.matrix.renders[%d].version", [i]),
	}
}

# (4) The digest drift: a fabric that re-rendered after the digest
# changed — the manifest's artifact and the fabric's render no
# longer describe the same bytes.
j_render_digest_drift contains finding if {
	some i, x in render_rows
	render_row_well_formed(x)
	fabric_declared(render_fabric(x))
	is_artifact_digest(package_digest)
	render_digest(x) != package_digest
	finding := {
		"severity": "error",
		"rule": "gate/render-digest-drift",
		"message": sprintf("fabric '%v' renders the digest %v, but the package manifest publishes %v: the re-render drifted from the package's artifact (%s, %s)", [render_fabric(x), render_digest(x), package_digest, matrix_file, package_file]),
		"path": sprintf("$.matrix.renders[%d].digest", [i]),
	}
}

# (5) The binding missing from a fabric: the package declares a
# policy binding every render must hold in force, and one fabric
# never rendered it.
j_binding_missing contains finding if {
	package_bindings_readable
	some d in declared_bindings
	some fabric in declared_fabrics
	fabric_rendered(fabric)
	not binding_in_force(fabric, d)
	finding := {
		"severity": "error",
		"rule": "gate/binding-missing",
		"message": sprintf("the package declares the policy binding '%v' at '%v', but fabric '%v' does not hold it in force: a binding missing from one fabric is a policy that fabric never ran (%s, %s)", [binding_policy(d), binding_path(d), fabric, package_file, matrix_file]),
		"path": "$.package.policyBindings",
	}
}

# (6) The binding nobody declared: a fabric holding a policy
# binding the package never shipped — the mirror image of the
# missing binding, and just as silent without the gate.
j_binding_undeclared contains finding if {
	package_bindings_readable
	some fabric in declared_fabrics
	some b in fabric_bindings(fabric)
	not binding_declared_in_manifest(b)
	finding := {
		"severity": "error",
		"rule": "gate/binding-undeclared",
		"message": sprintf("fabric '%v' holds the policy binding '%v' at '%v' in force, but the package manifest never declared it: a fabric enforcing a binding the package never shipped drifts silently (%s, %s)", [fabric, binding_policy(b), binding_path(b), matrix_file, package_file]),
		"path": sprintf("$.matrix.renders", []),
	}
}

# --- the fabric cards: the verdict the playground renders ---------------------------

# The board: one card per declared fabric — rendered at the
# manifest's version and digest with every declared binding in
# force (consistent), or the first divergence named. The cards
# render only when the join can be asked: both documents readable,
# the fabrics countable, the package's bindings readable.
fabric_cards := [card |
	some fabric in declared_fabrics
	card := fabric_card(fabric)
] if cards_renderable

fabric_cards := [] if not cards_renderable

cards_renderable if {
	is_object(matrix_doc)
	count(declared_fabrics) == count(as_array(matrix_doc, "fabrics"))
	lib.is_nonempty_string(package_component)
	lib.is_nonempty_string(package_version)
	is_artifact_digest(package_digest)
	package_bindings_readable
}

fabric_card(fabric) := {
	"fabric": fabric,
	"verdict": fabric_card_verdict(fabric),
	"detail": fabric_card_detail(fabric),
}

fabric_card_verdict(fabric) := "drifts" if fabric_card_drifts(fabric)

fabric_card_verdict(fabric) := "consistent" if not fabric_card_drifts(fabric)

fabric_card_drifts(fabric) if {
	not fabric_rendered(fabric)
}

fabric_card_drifts(fabric) if {
	fabric_rendered(fabric)
	fabric_first_row(fabric).version != package_version
}

fabric_card_drifts(fabric) if {
	fabric_rendered(fabric)
	fabric_first_row(fabric).digest != package_digest
}

fabric_card_drifts(fabric) if {
	fabric_rendered(fabric)
	some d in declared_bindings
	not binding_in_force(fabric, d)
}

fabric_card_drifts(fabric) if {
	fabric_rendered(fabric)
	some b in fabric_bindings(fabric)
	not binding_declared_in_manifest(b)
}

# The first render row in document order — the row the card reads,
# deterministically. A duplicate row is the validator's finding,
# never an ambiguity here.
fabric_first_row(fabric) := rows[0] if {
	rows := render_rows_for(fabric)
	count(rows) > 0
}

fabric_card_detail(fabric) := sprintf("no render row: coverage claimed and never delivered (%s)", [matrix_file]) if {
	not fabric_rendered(fabric)
}

fabric_card_detail(fabric) := sprintf("renders v%v against the manifest's v%v (%s, %s)", [fabric_first_row(fabric).version, package_version, matrix_file, package_file]) if {
	fabric_rendered(fabric)
	fabric_first_row(fabric).version != package_version
}

fabric_card_detail(fabric) := sprintf("renders the digest %v against the manifest's %v (%s, %s)", [fabric_first_row(fabric).digest, package_digest, matrix_file, package_file]) if {
	fabric_rendered(fabric)
	fabric_first_row(fabric).version == package_version
	fabric_first_row(fabric).digest != package_digest
}

fabric_card_detail(fabric) := sprintf("the declared binding '%v' at '%v' is not in force (%s, %s)", [binding_policy(missing_binding(fabric)), binding_path(missing_binding(fabric)), package_file, matrix_file]) if {
	fabric_rendered(fabric)
	fabric_first_row(fabric).version == package_version
	fabric_first_row(fabric).digest == package_digest
	count(missing_bindings(fabric)) > 0
}

fabric_card_detail(fabric) := sprintf("holds the binding '%v' at '%v' the package never declared (%s, %s)", [binding_policy(undeclared_binding(fabric)), binding_path(undeclared_binding(fabric)), matrix_file, package_file]) if {
	fabric_rendered(fabric)
	fabric_first_row(fabric).version == package_version
	fabric_first_row(fabric).digest == package_digest
	count(missing_bindings(fabric)) == 0
	count(undeclared_bindings(fabric)) > 0
}

fabric_card_detail(fabric) := sprintf("renders v%v at the manifest's digest with %d declared policy binding(s) in force (%s, %s)", [package_version, count([d | some d in declared_bindings; binding_in_force(fabric, d)]), matrix_file, package_file]) if {
	fabric_rendered(fabric)
	fabric_first_row(fabric).version == package_version
	fabric_first_row(fabric).digest == package_digest
	count(missing_bindings(fabric)) == 0
	count(undeclared_bindings(fabric)) == 0
}

# The declared bindings this fabric never rendered, in document
# order; the undeclared bindings it did. The card cites the first of
# each, deterministically.
missing_bindings(fabric) := [d |
	some d in declared_bindings
	not binding_in_force(fabric, d)
]

undeclared_bindings(fabric) := [b |
	some b in fabric_bindings(fabric)
	not binding_declared_in_manifest(b)
]

missing_binding(fabric) := b if {
	bs := missing_bindings(fabric)
	count(bs) > 0
	b := bs[0]
}

undeclared_binding(fabric) := b if {
	bs := undeclared_bindings(fabric)
	count(bs) > 0
	b := bs[0]
}

# --- the verdict ladder ------------------------------------------------------------

# The conformance ladder, honest about what each rung means: a
# document the gate cannot read is a question the gate refuses to
# answer; drifts are consistency failures the fabrics must fix
# before the render is believed; a matrix whose every fabric
# renders the manifest's version and digest with every declared
# binding in force is consistent.
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

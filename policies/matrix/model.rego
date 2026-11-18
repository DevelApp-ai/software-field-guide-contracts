# The shared model for the render-matrix consistency gate — The
# Software Field Guide, issue #102.
#
# Two documents enter: the COMPONENT PACKAGE MANIFEST (the package's
# own word — the component, the version, the sha256 artifact digest it
# publishes, and the policy bindings it declares, each bound to the
# exact path it renders from) and the RENDER MATRIX (the fabrics'
# answer — the fabrics the matrix covers, and each fabric's rendered
# copy of the package: the version it renders, the digest it rendered,
# and the policy bindings it holds in force). One component, N
# fabrics: every fabric's render must agree with the manifest on
# version, digest, and policy bindings, and every fabric in the
# matrix must have a render at all. The gate is the segment
# render-consistency pattern (#80) generalized from network rules to
# component packages. Every accessor here guards its input before
# touching object fields — a malformed document must produce
# findings, never a WASM trap.
package matrix

import rego.v1

import data.matrix.lib

# --- the input documents ------------------------------------------------------

package_doc := v if {
	is_object(input)
	v := object.get(input, "package", null)
}

package_doc := null if not is_object(input)

matrix_doc := v if {
	is_object(input)
	v := object.get(input, "matrix", null)
}

matrix_doc := null if not is_object(input)

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

matrix_file := v if {
	is_object(input)
	v := object.get(input, "matrixFile", "the render matrix")
}

matrix_file := "the render matrix" if not is_object(input)

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

# --- the package manifest: the fields the join reads -------------------------------

# The matrix gate composes on the component package conformance
# validator (#101): the package's own conformance — its registry
# admission, its signature, its attestation — is that gate's word.
# This gate reads only what the render join needs: the component's
# name, the version every fabric must render, the artifact digest
# every fabric must have rendered, and the policy bindings every
# fabric must hold in force.
package_component := object.get(package_doc, "component", null)

package_version := object.get(package_doc, "version", null)

package_digest := object.get(package_doc, "artifactDigest", null)

# The package's declared policy bindings: the policies that must be
# in force wherever the component renders, each bound to the exact
# path it renders from. Absent, the package declares none — and a
# fabric holding a binding the package never declared is drift.
package_bindings_present if {
	is_object(package_doc)
	object.get(package_doc, "policyBindings", null) != null
}

package_bindings := [b | some b in as_array(package_doc, "policyBindings"); is_object(b)]

binding_policy(b) := object.get(b, "policy", null)

binding_path(b) := object.get(b, "path", null)

# A binding row a join can trust: a named policy bound to a named
# path. Shape quality beyond this is the validator's finding, never
# an ambiguity for lookups.
binding_row_well_formed(b) if {
	is_object(b)
	lib.is_nonempty_string(binding_policy(b))
	lib.is_nonempty_string(binding_path(b))
}

# The well-formed declared bindings, in document order.
declared_bindings := [b | some b in package_bindings; binding_row_well_formed(b)]

# The package bindings are readable when the field is absent (the
# package declares none) or an array — malformed rows are findings,
# and the joins judge the well-formed subset.
package_bindings_readable if {
	not package_bindings_present
}

package_bindings_readable if {
	is_object(package_doc)
	is_array(object.get(package_doc, "policyBindings", null))
}

# A binding the manifest declares, judged by the pair — the same
# policy at a different path is a different binding, and both
# directions of that disagreement are findings.
binding_declared_in_manifest(b) if {
	some d in declared_bindings
	binding_policy(d) == binding_policy(b)
	binding_path(d) == binding_path(b)
}

# --- the render matrix: the stamps and the component it names ------------------------

matrix_component := object.get(matrix_doc, "component", null)

# --- the render matrix: the declared fabrics ------------------------------------------

fabric_names := [f | some f in as_array(matrix_doc, "fabrics"); is_string(f)]

# The declared fabrics, sorted — the N in "one component, N
# fabrics". Every fabric here must have a render; the join iterates
# this list, not the rows.
declared_fabrics := sort({f |
	some f in fabric_names
	lib.is_nonempty_string(f)
})

fabric_declared(fabric) if {
	some f in declared_fabrics
	f == fabric
}

# --- the render matrix: the render rows -------------------------------------------------

render_rows := [x | some x in as_array(matrix_doc, "renders"); is_object(x)]

render_fabric(x) := object.get(x, "fabric", null)

render_version(x) := object.get(x, "version", null)

render_digest(x) := object.get(x, "digest", null)

render_binding_rows(x) := [b | some b in as_array(x, "bindings"); is_object(b)]

# A render row a join can trust: its fabric named, the version it
# rendered named, the digest it rendered a real sha256, and its
# bindings an array. The fabric being declared is the join's own
# question (render/fabric-undeclared); the bindings' own shapes are
# their own findings.
render_row_well_formed(x) if {
	is_object(x)
	lib.is_nonempty_string(render_fabric(x))
	lib.is_nonempty_string(render_version(x))
	is_artifact_digest(render_digest(x))
	is_array(object.get(x, "bindings", null))
}

# The well-formed render rows of one declared fabric, in document
# order. A duplicate row is the validator's finding, never an
# ambiguity here — the first row is the one the cards read.
render_rows_for(fabric) := [x |
	some x in render_rows
	render_row_well_formed(x)
	render_fabric(x) == fabric
]

fabric_rendered(fabric) if {
	count(render_rows_for(fabric)) > 0
}

# The well-formed policy bindings one fabric holds in force, across
# its well-formed render rows.
fabric_bindings(fabric) := [b |
	some x in render_rows_for(fabric)
	some b in render_binding_rows(x)
	binding_row_well_formed(b)
]

# A declared binding is in force on a fabric when some binding the
# fabric rendered matches the pair — the same policy at the same
# path.
binding_in_force(fabric, d) if {
	some b in fabric_bindings(fabric)
	binding_policy(b) == binding_policy(d)
	binding_path(b) == binding_path(d)
}

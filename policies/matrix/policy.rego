# The render matrix validated alone — The Software Field Guide,
# issue #102.
#
# Every finding below judges ONE document: the render matrix, the
# fabrics' answer to the component package manifest — the fabrics
# the matrix covers, and each fabric's rendered copy of the package
# (the version it renders, the digest it rendered, and the policy
# bindings it holds in force). The joins live in the gate: a fabric
# running a different version, a digest mismatched against the
# manifest, a policy binding missing from one fabric, a fabric with
# no render at all — those are judged where the matrix meets the
# manifest.
package matrix

import rego.v1

import data.matrix.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_findings := ((((((((((((((f_input_invalid | f_today_invalid) | f_matrix_missing) | f_matrix_stamps) | f_matrix_component) | f_fabrics_array) | f_fabrics_content) | f_renders_array) | f_render_content) | f_render_shape) | f_render_refs) | f_render_dupes) | f_binding_must_be_object) | f_binding_policy_required) | f_binding_path_required) | f_binding_duplicate

# --- findings: the input and the clock ------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the render matrix as input.matrix",
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

# --- findings: the render matrix document -----------------------------------------

f_matrix_missing contains finding if {
	is_object(input)
	not is_object(matrix_doc)
	finding := {
		"severity": "error",
		"rule": "matrix/missing",
		"message": "the render matrix is required: pass it as input.matrix — one component, N fabrics, and the matrix is how the N answer",
		"path": "$.matrix",
	}
}

# The render matrix is an owned, versioned artifact: a matrix nobody
# re-reads a matrix nobody still believes.
f_matrix_stamps contains finding if {
	is_object(matrix_doc)
	not is_positive_integer(object.get(matrix_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "matrix/version-required",
		"message": sprintf("the render matrix must carry a version (a positive integer): the matrix is versioned like the package it renders (%s)", [matrix_file]),
		"path": "$.matrix.version",
	}
}

f_matrix_stamps contains finding if {
	is_object(matrix_doc)
	not lib.is_valid_date(object.get(matrix_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "matrix/reviewed-on-invalid",
		"message": sprintf("the render matrix must carry reviewedOn as a real YYYY-MM-DD date (%s)", [matrix_file]),
		"path": "$.matrix.reviewedOn",
	}
}

f_matrix_stamps contains finding if {
	is_object(matrix_doc)
	lib.is_valid_date(object.get(matrix_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(matrix_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "matrix/reviewed-in-future",
		"message": sprintf("the render matrix carries a reviewedOn date in the future (%s)", [matrix_file]),
		"path": "$.matrix.reviewedOn",
	}
}

f_matrix_stamps contains finding if {
	is_object(matrix_doc)
	lib.is_valid_date(object.get(matrix_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(matrix_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "matrix/reviewed-stale",
		"message": sprintf("the render matrix was reviewed more than 365 days before today: a matrix nobody re-renders is a matrix the fabrics silently left behind (%s)", [matrix_file]),
		"path": "$.matrix.reviewedOn",
	}
}

f_matrix_stamps contains finding if {
	is_object(matrix_doc)
	not lib.is_nonempty_string(object.get(matrix_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "matrix/owner-required",
		"message": sprintf("the render matrix must name an owner: a matrix without an owner is coverage nobody maintains (%s)", [matrix_file]),
		"path": "$.matrix.owner",
	}
}

# The matrix names the component it renders — the join's first
# question, and a finding the gate cites before any fabric is
# judged.
f_matrix_component contains finding if {
	is_object(matrix_doc)
	not lib.is_nonempty_string(matrix_component)
	finding := {
		"severity": "error",
		"rule": "matrix/component-required",
		"message": sprintf("the render matrix must name the component it renders: a matrix for no component is a matrix that renders nothing in particular (%s)", [matrix_file]),
		"path": "$.matrix.component",
	}
}

# --- findings: the declared fabrics --------------------------------------------------

f_fabrics_array contains finding if {
	is_object(matrix_doc)
	not is_array(object.get(matrix_doc, "fabrics", null))
	finding := {
		"severity": "error",
		"rule": "fabrics/must-be-array",
		"message": sprintf("fabrics must be an array of the fabric names the matrix covers (%s)", [matrix_file]),
		"path": "$.matrix.fabrics",
	}
}

f_fabrics_array contains finding if {
	is_object(matrix_doc)
	is_array(object.get(matrix_doc, "fabrics", null))
	count(declared_fabrics) == 0
	finding := {
		"severity": "error",
		"rule": "fabrics/required",
		"message": sprintf("the render matrix must declare at least one fabric: one component with no fabrics to render it is a component rendered nowhere (%s)", [matrix_file]),
		"path": "$.matrix.fabrics",
	}
}

f_fabrics_content contains finding if {
	some i, f in as_array(matrix_doc, "fabrics")
	not lib.is_nonempty_string(f)
	finding := {
		"severity": "error",
		"rule": "fabric/name-required",
		"message": sprintf("fabric entry %d must carry a non-empty name: an unnamed fabric cannot be cited in a finding (%s)", [i, matrix_file]),
		"path": sprintf("$.matrix.fabrics[%d]", [i]),
	}
}

f_fabrics_content contains finding if {
	some name in fabric_names
	lib.is_nonempty_string(name)
	count([f | some f in fabric_names; f == name]) > 1
	finding := {
		"severity": "error",
		"rule": "fabric/name-duplicate",
		"message": sprintf("fabric '%s' is declared more than once: a fabric declared twice is a render the gate cannot count (%s)", [name, matrix_file]),
		"path": "$.matrix.fabrics",
	}
}

# --- findings: the render rows ---------------------------------------------------------

f_renders_array contains finding if {
	is_object(matrix_doc)
	not is_array(object.get(matrix_doc, "renders", null))
	finding := {
		"severity": "error",
		"rule": "renders/must-be-array",
		"message": sprintf("the render rows must be an array of {fabric, version, digest, bindings} rows (%s)", [matrix_file]),
		"path": "$.matrix.renders",
	}
}

f_renders_array contains finding if {
	is_object(matrix_doc)
	is_array(object.get(matrix_doc, "renders", null))
	count(render_rows) == 0
	finding := {
		"severity": "error",
		"rule": "renders/rows-required",
		"message": sprintf("the render matrix must carry at least one render row: a matrix with no rows renders nothing (%s)", [matrix_file]),
		"path": "$.matrix.renders",
	}
}

f_render_content contains finding if {
	some i, x in as_array(matrix_doc, "renders")
	not is_object(x)
	finding := {
		"severity": "error",
		"rule": "renders/row-must-be-object",
		"message": sprintf("render row %d must be an object with fabric, version, digest, and bindings (%s)", [i, matrix_file]),
		"path": sprintf("$.matrix.renders[%d]", [i]),
	}
}

f_render_shape contains finding if {
	some i, x in render_rows
	not render_row_well_formed(x)
	finding := {
		"severity": "error",
		"rule": "render/row-invalid",
		"message": sprintf("render row %d must carry its fabric and the version it renders (non-empty strings), the digest it rendered as a real sha256, and its bindings as an array (%s)", [i, matrix_file]),
		"path": sprintf("$.matrix.renders[%d]", [i]),
	}
}

# --- findings: the render rows' references ---------------------------------------------

# A render row on a fabric the matrix never declared: the join can
# only count fabrics the matrix declares.
f_render_refs contains finding if {
	some i, x in render_rows
	render_row_well_formed(x)
	not fabric_declared(render_fabric(x))
	finding := {
		"severity": "error",
		"rule": "render/fabric-undeclared",
		"message": sprintf("a render row cites fabric '%s', which the matrix never declared in fabrics: either the row renders onto a fabric nobody owns, or the fabric list forgot a fabric — the two disagree (%s)", [render_fabric(x), matrix_file]),
		"path": sprintf("$.matrix.renders[%d].fabric", [i]),
	}
}

# The same fabric rendered twice: a render the gate cannot count is
# a render that hides the missing one.
f_render_dupes contains finding if {
	some fabric in declared_fabrics
	count(render_rows_for(fabric)) > 1
	finding := {
		"severity": "error",
		"rule": "render/row-duplicate",
		"message": sprintf("fabric '%s' is rendered %d times: two render rows for one fabric is a render nobody can diff (%s)", [fabric, count(render_rows_for(fabric)), matrix_file]),
		"path": "$.matrix.renders",
	}
}

# --- findings: the rendered policy bindings ----------------------------------------------

f_binding_must_be_object contains finding if {
	some i, x in render_rows
	some b in as_array(x, "bindings")
	not is_object(b)
	finding := {
		"severity": "error",
		"rule": "render/binding-must-be-object",
		"message": sprintf("every rendered binding must be an object: {policy, path} (%s)", [matrix_file]),
		"path": sprintf("$.matrix.renders[%d].bindings", [i]),
	}
}

f_binding_policy_required contains finding if {
	some i, x in render_rows
	some b in render_binding_rows(x)
	not lib.is_nonempty_string(binding_policy(b))
	finding := {
		"severity": "error",
		"rule": "render/binding-policy-required",
		"message": sprintf("every rendered binding must name the policy it binds (%s)", [matrix_file]),
		"path": sprintf("$.matrix.renders[%d].bindings", [i]),
	}
}

f_binding_path_required contains finding if {
	some i, x in render_rows
	some b in render_binding_rows(x)
	not lib.is_nonempty_string(binding_path(b))
	finding := {
		"severity": "error",
		"rule": "render/binding-path-required",
		"message": sprintf("every rendered binding must name the exact path it renders from: a binding pinned to no path is a binding that can point anywhere (%s)", [matrix_file]),
		"path": sprintf("$.matrix.renders[%d].bindings", [i]),
	}
}

f_binding_duplicate contains finding if {
	some i, x in render_rows
	some b in render_binding_rows(x)
	binding_row_well_formed(b)
	count([y |
		some y in render_binding_rows(x)
		binding_row_well_formed(y)
		binding_policy(y) == binding_policy(b)
		binding_path(y) == binding_path(b)
	]) > 1
	finding := {
		"severity": "error",
		"rule": "render/binding-duplicate",
		"message": sprintf("the binding '%s' at '%s' is rendered more than once on fabric '%s': one policy at one path, once per fabric (%s)", [binding_policy(b), binding_path(b), render_fabric(x), matrix_file]),
		"path": sprintf("$.matrix.renders[%d].bindings", [i]),
	}
}

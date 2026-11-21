# Policy-component validation gate — The Software Field Guide,
# issue #103.
#
# A policy component is a component like any other: versioned,
# signed over its digest, and — the part this gate adds — bound to
# exactly one path and sitting on one rung of the audit→warn→enforce
# posture ladder. The gate joins the POLICY COMPONENT CATALOG (the
# platform's word: the policy components it admits, each at its
# canonical exact path) against the COMPONENT PACKAGE MANIFEST's
# policyBindings (the package's word: the policies it binds and the
# exact path each renders from) and refuses — a conformance gate,
# not an advisor. The two drifts the gate knows by name: a binding to
# a policy the catalog never declared (gate/policy-unresolved) and a
# binding rendered at a path the catalog never named
# (gate/binding-path-drift). "Every policy component referenced by a
# package must exist and vice versa" is honest here the way it is
# everywhere in this repo: the join is a pair agreement, not an
# inventory demand — the same catalog backs many packages, so a
# catalog row no package currently binds is a policy available, not
# a drift. What also fails the gate is a document the gate cannot
# read — broken stamps or shapes are a question the gate refuses to
# answer on its own inputs, and the package-side exactness gap the
# component gate never checks (a glob-shaped binding path) is caught
# here (package/binding-path-glob), because the join refuses to
# guess what a wildcard matched. The verdict ladder separates the
# failures honestly: unreadable (a document is malformed), drifts
# (only join drifts), consistent. The gate composes on the component
# package conformance validator (#101): the package's own
# conformance is that gate's word; this gate reads only what the
# policy join needs.
#
# Input (JSON): {"catalog": {...}, "package": {...},
#                "today": "YYYY-MM-DD", "catalogFile": "...",
#                "packageFile": "..."}
# Result:       {"valid": bool, "findings": [...], "policies": [...], "verdict": "..."}
package policy

import rego.v1

import data.policy.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"policies": policy_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := (validate_findings | package_findings) | join_findings

# --- findings: the package manifest at the gate --------------------------------

# The join cannot run without the package's bindings — and this gate
# re-checks the exactness the component gate (#101) never judged:
# the bindings are read as they are shipped, so a glob-shaped path is
# a binding the gate refuses to guess. The package's own conformance
# — names, tiers, digests, registry admission — is the component
# gate's word; this gate requires only what the policy join reads,
# and says so.
package_findings := (((((p_package_missing | p_bindings_must_be_array) | p_binding_must_be_object) | p_binding_policy_required) | p_binding_path_required) | p_binding_path_glob) | p_binding_duplicate

p_package_missing contains finding if {
	not is_object(package_doc)
	finding := {
		"severity": "error",
		"rule": "package/missing",
		"message": sprintf("the component package manifest is required at the gate: pass it as input.package — the package's policy bindings are judged against the catalog's word (%s)", [package_file]),
		"path": "$.package",
	}
}

# The declared policy bindings, when the package declares any: an
# array of {policy, path} rows. Absent is honest — the package binds
# no policies — but a present-and-malformed field is a document the
# gate cannot read.
p_bindings_must_be_array contains finding if {
	is_object(package_doc)
	object.get(package_doc, "policyBindings", null) != null
	not is_array(object.get(package_doc, "policyBindings", null))
	finding := {
		"severity": "error",
		"rule": "package/bindings-must-be-array",
		"message": sprintf("the package manifest's policyBindings must be an array of {policy, path} rows: the policies the package binds to its render (%s)", [package_file]),
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

# The package-side exactness rule: the component validator (#101)
# never asked whether a binding path is exact — it validates the
# package, not the policy join. This gate does: a glob-shaped
# binding path is a binding claiming every path it can match, and
# the join refuses to guess.
p_binding_path_glob contains finding if {
	some b in package_bindings
	lib.is_nonempty_string(binding_path(b))
	not is_exact_path(binding_path(b))
	finding := {
		"severity": "error",
		"rule": "package/binding-path-glob",
		"message": sprintf("the package binds the policy '%v' at the glob-shaped path '%v': a binding must be an exact path — '%v' can match anything, and the join refuses to guess what (%s)", [binding_policy(b), binding_path(b), binding_path(b), package_file]),
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
		"message": sprintf("the policy '%v' is bound more than once: one policy, one binding — a policy bound twice is a binding nobody can diff (%s)", [binding_policy(b), package_file]),
		"path": "$.package.policyBindings",
	}
}

# --- the two drifts, named ------------------------------------------------------

join_findings := j_policy_unresolved | j_binding_path_drift

# (1) The unresolved binding: the package names a policy to hold in
# force, and the catalog — the platform's only word on what exists —
# never declared it. A deny-by-default claim about a policy that
# does not exist is a claim nobody can check.
j_policy_unresolved contains finding if {
	package_bindings_readable
	some d in declared_bindings
	not catalog_declares(binding_policy(d))
	finding := {
		"severity": "error",
		"rule": "gate/policy-unresolved",
		"message": sprintf("the package binds the policy '%v', but the catalog never declared it: a binding to a policy the estate never admitted is a deny-by-default claim nobody can check (%s, %s)", [binding_policy(d), package_file, catalog_file]),
		"path": "$.package.policyBindings",
	}
}

# (2) The path drift: the package binds a policy the catalog
# admits, but renders it from a path the catalog never named. The
# pair is the agreement — the same policy at a different path is a
# different binding, and which one is in force is exactly the
# question a deny-by-default posture claims to answer.
j_binding_path_drift contains finding if {
	package_bindings_readable
	some d in declared_bindings
	catalog_declares(binding_policy(d))
	row := row_for(binding_policy(d))
	is_exact_path(row_path(row))
	row_path(row) != binding_path(d)
	finding := {
		"severity": "error",
		"rule": "gate/binding-path-drift",
		"message": sprintf("the package binds '%v' at '%v', but the catalog declares it at '%v': the same policy at a different path is a binding nobody can prove is the one in force (%s, %s)", [binding_policy(d), binding_path(d), row_path(row), package_file, catalog_file]),
		"path": "$.package.policyBindings",
	}
}

# --- the policy cards: the verdict the playground renders ---------------------------

# The board: one card per BOUND policy — resolved to a catalog row
# declared at the binding's exact path (consistent), or the first
# divergence named. The cards render only when the join can be
# asked: both documents readable, the package's bindings readable,
# the catalog's rows readable in full shape. A catalog row no
# package binds is a card that does not render — the shared catalog
# is judged at the join, not by inventory.
policy_cards := [card |
	some name in bound_policy_names
	card := policy_card(name)
] if cards_renderable

policy_cards := [] if not cards_renderable

cards_renderable if {
	is_object(catalog_doc)
	is_object(package_doc)
	catalog_rows_readable
	package_bindings_readable
	count(declared_bindings) == count(package_bindings)
}

policy_card(name) := {
	"policy": name,
	"verdict": policy_card_verdict(name),
	"detail": policy_card_detail(name),
}

policy_card_verdict(name) := "drifts" if policy_card_drifts(name)

policy_card_verdict(name) := "consistent" if not policy_card_drifts(name)

policy_card_drifts(name) if {
	not catalog_declares(name)
}

policy_card_drifts(name) if {
	catalog_declares(name)
	row := row_for(name)
	row_path(row) != bound_path_for(name)
}

# The exact path the package binds a policy at, in document order;
# duplicates are the gate's finding, and the card reads the first.
bound_path_for(name) := p if {
	paths := [binding_path(b) |
		some b in declared_bindings
		binding_policy(b) == name
	]
	count(paths) > 0
	p := paths[0]
}

policy_card_detail(name) := sprintf("bound to the package but missing from the catalog: a deny-by-default claim nobody can check (%s, %s)", [package_file, catalog_file]) if {
	not catalog_declares(name)
}

policy_card_detail(name) := sprintf("the package binds it at '%v', but the catalog declares it at '%v' (%s, %s)", [bound_path_for(name), row_path(row_for(name)), package_file, catalog_file]) if {
	catalog_declares(name)
	row_path(row_for(name)) != bound_path_for(name)
}

policy_card_detail(name) := sprintf("bound at the catalog's exact path '%v', posture '%v' on the ladder (%s, %s)", [bound_path_for(name), row_posture(row_for(name)), package_file, catalog_file]) if {
	catalog_declares(name)
	row_path(row_for(name)) == bound_path_for(name)
}

# --- the verdict ladder ------------------------------------------------------------

# The conformance ladder, honest about what each rung means: a
# document the gate cannot read is a question the gate refuses to
# answer; drifts are pair failures the package must fix before its
# policy posture is believed consistent; a package whose every
# binding resolves to a catalog row at the exact declared path is
# consistent.
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

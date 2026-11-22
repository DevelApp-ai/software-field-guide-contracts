# Component-lifecycle consistency gate — The Software Field Guide,
# issue #105.
#
# A transition recorded once and never refreshed is a question, not a
# fact: a paper trail drifts silently when it documents a component
# the package manifest never packaged. This gate joins the lifecycle
# record (the component's own word — the bake that produced its
# image, the patch folded in, the upgrade with its rehearsed
# rollback) against the component package manifest (the package's
# word — the component it published) and refuses: a conformance
# gate, not an advisor. The one drift the gate knows by name is the
# mismatched join: a record for a component the manifest never
# packaged (gate/component-mismatch). What also fails the gate is a
# document the gate cannot read — a record with broken stamps, a
# transition without its evidence, a manifest without a name is a
# question the gate refuses to answer on its own inputs. The verdict
# ladder separates the two honestly: unreadable (a document is
# malformed), drifts (only join drifts), consistent. The gate
# composes on the component package conformance validator (#101):
# the package's own conformance is that gate's word; this gate reads
# only what the join needs — the manifest's component name.
#
# Input (JSON): {"lifecycle": {...}, "package": {...},
#                "today": "YYYY-MM-DD", "lifecycleFile": "...",
#                "packageFile": "..."}
# Result:       {"valid": bool, "findings": [...], "transitions": [...], "verdict": "..."}
package lifecycle

import rego.v1

import data.lifecycle.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"transitions": transition_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := (validate_findings | package_findings) | join_findings

# --- findings: the package manifest at the gate --------------------------------

# The join cannot run without the package's word: the component's
# name. The package's own conformance — registry admission,
# signature, attestation — is the component gate's word (#101);
# this gate requires only what the lifecycle join reads, and says
# so.
package_findings := p_package_missing | p_component_required

p_package_missing contains finding if {
	not is_object(package_doc)
	finding := {
		"severity": "error",
		"rule": "package/missing",
		"message": sprintf("the component package manifest is required at the gate: pass it as input.package — the record's transitions are joined to the package by name (%s)", [package_file]),
		"path": "$.package",
	}
}

p_component_required contains finding if {
	is_object(package_doc)
	not lib.is_nonempty_string(package_component)
	finding := {
		"severity": "error",
		"rule": "component/name-required",
		"message": sprintf("the package manifest must name the component it packages: the lifecycle record is joined to the package by name (%s)", [package_file]),
		"path": "$.package.component",
	}
}

# --- the one drift, named -------------------------------------------------------

join_findings := j_component_mismatch

# The mismatched join: the record documents a component the manifest
# never packaged. The join cannot even be asked.
j_component_mismatch contains finding if {
	is_object(lifecycle_doc)
	is_object(package_doc)
	lib.is_nonempty_string(record_component)
	lib.is_nonempty_string(package_component)
	record_component != package_component
	finding := {
		"severity": "error",
		"rule": "gate/component-mismatch",
		"message": sprintf("the lifecycle record documents '%v', but the package manifest packages '%v': the paper trail is answering for somebody else's component (%s, %s)", [record_component, package_component, lifecycle_file, package_file]),
		"path": "$.lifecycle.component",
	}
}

# --- the transition cards: the verdict the playground renders ------------------

# The board: one card per well-formed recorded transition — the
# bake pinned at its image digest, the patch with its provenance,
# the upgrade with its rehearsed rollback (consistent), or the
# divergence named. The cards render only when the join can be
# asked: both documents readable, every transition row well-formed,
# and both component names present.
transition_cards := [card |
	some t in well_formed_rows
	card := transition_card(t)
] if cards_renderable

transition_cards := [] if not cards_renderable

cards_renderable if {
	is_object(lifecycle_doc)
	count(well_formed_rows) == count(as_array(lifecycle_doc, "transitions"))
	lib.is_nonempty_string(record_component)
	lib.is_nonempty_string(package_component)
}

transition_card(t) := {
	"type": transition_type(t),
	"verdict": transition_card_verdict(t),
	"detail": transition_card_detail(t),
}

transition_card_verdict(t) := "drifts" if transition_card_drifts(t)

transition_card_verdict(t) := "consistent" if not transition_card_drifts(t)

transition_card_drifts(t) if {
	record_component != package_component
}

transition_card_detail(t) := sprintf("the record documents '%v', but the package manifest packages '%v' (%s, %s)", [record_component, package_component, lifecycle_file, package_file]) if {
	transition_card_drifts(t)
}

transition_card_detail(t) := sprintf("bake recorded %v at the image digest %v, evidenced (%s, %s)", [transition_recorded_on(t), bake_image_digest(t), lifecycle_file, package_file]) if {
	not transition_card_drifts(t)
	transition_type(t) == "bake"
}

transition_card_detail(t) := sprintf("patch recorded %v with provenance to '%v' at commit %v, evidenced (%s, %s)", [transition_recorded_on(t), provenance_source(t), provenance_commit(t), lifecycle_file, package_file]) if {
	not transition_card_drifts(t)
	transition_type(t) == "patch"
}

transition_card_detail(t) := sprintf("upgrade recorded %v with a rollback rehearsed %v, evidenced (%s, %s)", [transition_recorded_on(t), rollback_rehearsed_on(t), lifecycle_file, package_file]) if {
	not transition_card_drifts(t)
	transition_type(t) == "upgrade"
}

# --- the verdict ladder ----------------------------------------------------------

# The conformance ladder, honest about what each rung means: a
# document the gate cannot read is a question the gate refuses to
# answer; a drift is a consistency failure the record must fix
# before the trail is believed; a record whose every transition
# carries its evidence, fresh and covered by its review, for the
# component the manifest packages, is consistent.
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

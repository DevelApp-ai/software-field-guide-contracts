# Compliance controls-as-data gate — The Software Field Guide, issue
# #107.
#
# Controls nobody maps to requirements are busywork; requirements
# nobody controls are promises nobody keeps; a control pointing at
# an evidence source the estate retired is a control nobody can
# audit; a control whose review clock has lapsed is a control nobody
# operates. This gate joins the controls manifest (the estate's own
# word — its named evidence sources and every control's mappings,
# citations, and review clocks) against the requirements catalog
# (compliance's answer — the requirements the estate must satisfy)
# and refuses — a conformance gate, not an advisor: a manifest the
# catalog disagrees with is compliance theater with data attached.
# The four drifts the gate knows by name: a requirement no control
# maps to (gate/requirement-unmapped), a control mapping to a
# requirement the catalog never declared (gate/requirement-unknown),
# a control citing a retired evidence source (gate/evidence-dead), and
# a control whose review clock has lapsed (gate/review-expired). What
# also fails the gate is a document the gate cannot read — a manifest
# or catalog with broken stamps or shapes is a question the gate
# refuses to answer on its own inputs. The verdict ladder separates
# the two honestly: unreadable (a document is malformed), drifts
# (only join drifts), consistent. The gate is honest about what it
# models: it checks that citations resolve and clocks have not
# lapsed — that the evidence store still holds its logs is outside
# what a policy can check, and the gate says so.
#
# Input (JSON): {"controls": {...}, "requirements": {...},
#                "today": "YYYY-MM-DD", "controlsFile": "...",
#                "requirementsFile": "..."}
# Result:       {"valid": bool, "findings": [...], "requirements": [...], "verdict": "..."}
package compliance

import rego.v1

import data.compliance.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"requirements": requirement_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := (validate_findings | catalog_findings) | join_findings

# --- findings: the requirements catalog at the gate --------------------------------
#
# The join cannot run without the catalog's word: the requirement ids
# the controls map onto, each a string the gate can cite. The
# catalog's own conformance beyond its ids — its titles, its sources,
# the prose of the obligation — is its owners' word; this gate reads
# only what the join needs, and says so.

catalog_findings := (((c_requirements_missing | c_requirements_must_be_array) | c_requirements_required) | c_row_must_be_object) | c_requirement_id_required

c_requirements_missing contains finding if {
	is_object(input)
	not is_object(requirements_doc)
	finding := {
		"severity": "error",
		"rule": "requirements/missing",
		"message": sprintf("the requirements catalog is required at the gate: pass it as input.requirements — the controls are judged against the requirements the estate must satisfy (%s)", [requirements_file]),
		"path": "$.requirements",
	}
}

c_requirements_must_be_array contains finding if {
	is_object(requirements_doc)
	not is_array(object.get(requirements_doc, "requirements", null))
	finding := {
		"severity": "error",
		"rule": "requirements/must-be-array",
		"message": sprintf("the catalog's requirements field must be an array of requirement rows (%s)", [requirements_file]),
		"path": "$.requirements.requirements",
	}
}

c_requirements_required contains finding if {
	is_object(requirements_doc)
	is_array(object.get(requirements_doc, "requirements", null))
	count(as_array(requirements_doc, "requirements")) == 0
	finding := {
		"severity": "error",
		"rule": "requirements/required",
		"message": sprintf("the requirements catalog declares no requirements: an empty catalog claims the estate must satisfy nothing (%s)", [requirements_file]),
		"path": "$.requirements.requirements",
	}
}

c_row_must_be_object contains finding if {
	some i, x in as_array(requirements_doc, "requirements")
	not is_object(x)
	finding := {
		"severity": "error",
		"rule": "requirements/row-must-be-object",
		"message": sprintf("every catalog requirement must be an object: {id, title, source} (%s)", [requirements_file]),
		"path": sprintf("$.requirements.requirements[%d]", [i]),
	}
}

c_requirement_id_required contains finding if {
	some i, x in requirement_rows
	not lib.is_nonempty_string(requirement_id(x))
	finding := {
		"severity": "error",
		"rule": "requirement/id-required",
		"message": sprintf("every catalog requirement needs an id: the controls map onto ids, and a row the join cannot cite is a row nobody satisfies (%s)", [requirements_file]),
		"path": sprintf("$.requirements.requirements[%d].id", [i]),
	}
}

# --- the four drifts, named ------------------------------------------------------

join_findings := ((j_requirement_unmapped | j_requirement_unknown) | j_evidence_dead) | j_review_expired

# (1) The unmapped requirement: the catalog names an obligation and
# no control maps onto it — a promise nobody keeps, cited as the
# requirement, with both documents.
j_requirement_unmapped contains finding if {
	some req in declared_requirements
	requirement_rows_readable
	not requirement_mapped(req)
	finding := {
		"severity": "error",
		"rule": "gate/requirement-unmapped",
		"message": sprintf("requirement '%v' has no control mapped to it: a requirement nobody controls is a promise nobody keeps (%s, %s)", [req, requirements_file, controls_file]),
		"path": "$.requirements.requirements",
	}
}

# (2) The unknown requirement: a control maps onto an id the catalog
# never declared — compliance claimed with words nobody wrote.
j_requirement_unknown contains finding if {
	some i, c in control_rows
	control_row_well_formed(c)
	some r in control_requirements(c)
	not requirement_declared(r)
	finding := {
		"severity": "error",
		"rule": "gate/requirement-unknown",
		"message": sprintf("control '%v' maps to requirement '%v', but the catalog never declared it: the control claims compliance with a requirement nobody wrote (%s, %s)", [control_id(c), r, controls_file, requirements_file]),
		"path": sprintf("$.controls.controls[%d].requirements", [i]),
	}
}

# (3) The dead evidence: a control citing a source the manifest
# itself retired — the citation resolves, but the estate no longer
# collects what it points at.
j_evidence_dead contains finding if {
	some i, c in control_rows
	control_row_well_formed(c)
	source_declared(control_evidence(c))
	source_status_retired(control_evidence(c))
	finding := {
		"severity": "error",
		"rule": "gate/evidence-dead",
		"message": sprintf("control '%v' cites the evidence source '%v', but the manifest retired that source: a control pointing at evidence nobody collects is a control nobody can audit (%s)", [control_id(c), control_evidence(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].evidenceSource", [i]),
	}
}

# (4) The lapsed clock: reviewedOn plus intervalDays falls before
# today — a control nobody re-reviews is a control nobody operates.
j_review_expired contains finding if {
	some i, c in control_rows
	control_row_well_formed(c)
	control_clock_expired(c)
	finding := {
		"severity": "error",
		"rule": "gate/review-expired",
		"message": sprintf("control '%v' was last reviewed on %v against a %d-day clock that has lapsed: a control nobody re-reviews is a control nobody operates (%s)", [control_id(c), control_reviewed_on(c), control_interval(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].reviewedOn", [i]),
	}
}

# --- the requirement cards: the verdict the playground renders ---------------------------

# The board: one card per declared requirement — covered by a sound
# control (a live evidence source, a fresh review clock), or the
# first problem named. The cards render only when the join can be
# asked: both documents readable, every catalog row citable, every
# control row well-formed, the evidence sources a readable array.
requirement_cards := [card |
	some req in declared_requirements
	card := requirement_card(req)
] if cards_renderable

requirement_cards := [] if not cards_renderable

cards_renderable if {
	is_object(controls_doc)
	is_object(requirements_doc)
	requirement_rows_readable
	controls_readable
	sources_readable
}

requirement_card(req) := {
	"requirement": req,
	"verdict": requirement_card_verdict(req),
	"detail": requirement_card_detail(req),
}

requirement_card_verdict(req) := "drifts" if not requirement_covered(req)

requirement_card_verdict(req) := "consistent" if requirement_covered(req)

requirement_card_detail(req) := sprintf("no control maps to it: coverage claimed and never delivered (%s, %s)", [requirements_file, controls_file]) if {
	not requirement_mapped(req)
}

requirement_card_detail(req) := sprintf("mapped by control '%v' but its evidence is dead: the source '%v' is retired (%s)", [control_id(first_problem_control(req)), control_evidence(first_problem_control(req)), controls_file]) if {
	requirement_mapped(req)
	count(problem_controls_for(req)) > 0
	source_status_retired(control_evidence(first_problem_control(req)))
}

requirement_card_detail(req) := sprintf("mapped by control '%v' but its review clock lapsed: last reviewed %v on a %d-day clock (%s)", [control_id(first_problem_control(req)), control_reviewed_on(first_problem_control(req)), control_interval(first_problem_control(req)), controls_file]) if {
	requirement_mapped(req)
	count(problem_controls_for(req)) > 0
	not source_status_retired(control_evidence(first_problem_control(req)))
	control_clock_expired(first_problem_control(req))
}

requirement_card_detail(req) := sprintf("mapped by control '%v' but its evidence citation '%v' resolves nowhere the manifest declares (%s)", [control_id(first_problem_control(req)), control_evidence(first_problem_control(req)), controls_file]) if {
	requirement_mapped(req)
	count(problem_controls_for(req)) > 0
	not source_status_retired(control_evidence(first_problem_control(req)))
	not control_clock_expired(first_problem_control(req))
}

requirement_card_detail(req) := sprintf("covered by control '%v' with live evidence '%v' and a fresh %d-day review clock (%s, %s)", [control_id(first_sound_control(req)), control_evidence(first_sound_control(req)), control_interval(first_sound_control(req)), controls_file, requirements_file]) if {
	count(sound_controls_for(req)) > 0
}

# --- the verdict ladder ------------------------------------------------------------

# The conformance ladder, honest about what each rung means: a
# document the gate cannot read is a question the gate refuses to
# answer; drifts are coverage failures the control owners must fix
# before the compliance story is believed; a catalog whose every
# requirement is covered by a sound control is consistent.
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

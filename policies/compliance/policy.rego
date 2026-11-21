# The controls manifest validated alone — The Software Field Guide,
# issue #107.
#
# Every finding below judges ONE document: the controls manifest, the
# estate's own word — the named evidence sources it collects and every
# control with its title, owner, mapped requirements, evidence
# citation, and review clock. The joins live in the gate: a
# requirement no control maps to, a control citing a requirement the
# catalog never declared, a control pointing at a retired source, a
# clock that has lapsed — those are judged where the manifest meets
# the requirements catalog.
package compliance

import rego.v1

import data.compliance.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_findings := ((((((((((f_input_invalid | f_today_invalid) | f_controls_missing) | f_controls_stamps) | f_controls_array) | f_controls_content) | f_control_shape) | f_control_clock) | f_control_dupes) | f_sources_array) | f_source_shape) | f_source_refs

# --- findings: the input and the clock ------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the controls manifest as input.controls",
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

# --- findings: the manifest document ----------------------------------------------

f_controls_missing contains finding if {
	is_object(input)
	not is_object(controls_doc)
	finding := {
		"severity": "error",
		"rule": "controls/missing",
		"message": "the controls manifest is required: pass it as input.controls — the estate's compliance work is judged through the controls it declares",
		"path": "$.controls",
	}
}

# The manifest is an owned, versioned artifact: controls nobody
# re-reads are controls the estate silently left behind.
f_controls_stamps contains finding if {
	is_object(controls_doc)
	not is_positive_integer(object.get(controls_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "controls/version-required",
		"message": sprintf("the controls manifest must carry a version (a positive integer): the controls are versioned data, like the requirements they satisfy (%s)", [controls_file]),
		"path": "$.controls.version",
	}
}

f_controls_stamps contains finding if {
	is_object(controls_doc)
	not lib.is_valid_date(object.get(controls_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "controls/reviewed-on-invalid",
		"message": sprintf("the controls manifest must carry reviewedOn as a real YYYY-MM-DD date (%s)", [controls_file]),
		"path": "$.controls.reviewedOn",
	}
}

f_controls_stamps contains finding if {
	is_object(controls_doc)
	lib.is_valid_date(object.get(controls_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(controls_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "controls/reviewed-in-future",
		"message": sprintf("the controls manifest carries a reviewedOn date in the future: a review that has not happened is not a review (%s)", [controls_file]),
		"path": "$.controls.reviewedOn",
	}
}

f_controls_stamps contains finding if {
	is_object(controls_doc)
	lib.is_valid_date(object.get(controls_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(controls_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "controls/reviewed-stale",
		"message": sprintf("the controls manifest was reviewed more than 365 days before today: a manifest nobody re-reads is a manifest the estate silently left behind (%s)", [controls_file]),
		"path": "$.controls.reviewedOn",
	}
}

f_controls_stamps contains finding if {
	is_object(controls_doc)
	not lib.is_nonempty_string(object.get(controls_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "controls/owner-required",
		"message": sprintf("the controls manifest must name an owner: controls without an owner are nobody's work (%s)", [controls_file]),
		"path": "$.controls.owner",
	}
}

# --- findings: the control rows -------------------------------------------------------

f_controls_array contains finding if {
	is_object(controls_doc)
	not is_array(object.get(controls_doc, "controls", null))
	finding := {
		"severity": "error",
		"rule": "controls/must-be-array",
		"message": sprintf("the manifest's controls field must be an array of control rows (%s)", [controls_file]),
		"path": "$.controls.controls",
	}
}

f_controls_array contains finding if {
	is_object(controls_doc)
	is_array(object.get(controls_doc, "controls", null))
	count(as_array(controls_doc, "controls")) == 0
	finding := {
		"severity": "error",
		"rule": "controls/required",
		"message": sprintf("the controls manifest declares no controls: an empty manifest claims the estate controls nothing (%s)", [controls_file]),
		"path": "$.controls.controls",
	}
}

f_controls_content contains finding if {
	some i, c in as_array(controls_doc, "controls")
	not is_object(c)
	finding := {
		"severity": "error",
		"rule": "control/row-must-be-object",
		"message": sprintf("every control must be an object: {id, title, owner, requirements, evidenceSource, reviewedOn, intervalDays} (%s)", [controls_file]),
		"path": sprintf("$.controls.controls[%d]", [i]),
	}
}

# The control's own fields: an id to cite, words an auditor can read,
# an owner who operates it, requirement ids it maps onto, and a named
# evidence source. The endpoint rows of the compliance chapter,
# checked shape first so the joins are never ambiguous.
f_control_shape contains finding if {
	some i, c in control_rows
	not lib.is_nonempty_string(control_id(c))
	finding := {
		"severity": "error",
		"rule": "control/id-required",
		"message": sprintf("every control needs an id: a control the gate cannot cite is a control nobody can answer for (%s)", [controls_file]),
		"path": sprintf("$.controls.controls[%d].id", [i]),
	}
}

f_control_shape contains finding if {
	some i, c in control_rows
	not lib.is_nonempty_string(control_title(c))
	finding := {
		"severity": "error",
		"rule": "control/title-required",
		"message": sprintf("control '%v' must state what it does: an untitled control is a finding nobody can explain to an auditor (%s)", [control_id(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].title", [i]),
	}
}

f_control_shape contains finding if {
	some i, c in control_rows
	not lib.is_nonempty_string(control_owner(c))
	finding := {
		"severity": "error",
		"rule": "control/owner-required",
		"message": sprintf("control '%v' must name its owner: a control without an owner is a control nobody operates (%s)", [control_id(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].owner", [i]),
	}
}

f_control_shape contains finding if {
	some i, c in control_rows
	object.get(c, "requirements", null) != null
	not is_array(object.get(c, "requirements", null))
	finding := {
		"severity": "error",
		"rule": "control/requirements-must-be-array",
		"message": sprintf("control '%v' must carry its requirements as an array of catalog ids (%s)", [control_id(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].requirements", [i]),
	}
}

f_control_shape contains finding if {
	some i, c in control_rows
	count(control_requirements(c)) == 0
	finding := {
		"severity": "error",
		"rule": "control/requirements-required",
		"message": sprintf("control '%v' maps to no requirements: every control exists to satisfy a requirement — an unmapped control is busywork with no compliance meaning (%s)", [control_id(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].requirements", [i]),
	}
}

f_control_shape contains finding if {
	some i, c in control_rows
	some r in as_array(c, "requirements")
	not is_string(r)
	finding := {
		"severity": "error",
		"rule": "control/requirement-must-be-string",
		"message": sprintf("control '%v' carries a requirement id that is not a string: the controls map onto the catalog's ids (%s)", [control_id(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].requirements", [i]),
	}
}

f_control_shape contains finding if {
	some i, c in control_rows
	not lib.is_nonempty_string(control_evidence(c))
	finding := {
		"severity": "error",
		"rule": "control/evidence-required",
		"message": sprintf("control '%v' names no evidence source: a control without evidence is an assertion, not a control (%s)", [control_id(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].evidenceSource", [i]),
	}
}

# The review clock's own shape — the lapse itself is the gate's
# judgment against the injected today, judged where the clock meets
# the requirement it protects.
f_control_clock contains finding if {
	some i, c in control_rows
	not lib.is_valid_date(control_reviewed_on(c))
	finding := {
		"severity": "error",
		"rule": "control/reviewed-on-invalid",
		"message": sprintf("control '%v' must carry reviewedOn as a real YYYY-MM-DD date — the review clock cannot read '%v' (%s)", [control_id(c), control_reviewed_on(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].reviewedOn", [i]),
	}
}

f_control_clock contains finding if {
	some i, c in control_rows
	lib.is_valid_date(control_reviewed_on(c))
	lib.is_valid_date(today_date)
	lib.date_to_days(control_reviewed_on(c)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "control/reviewed-in-future",
		"message": sprintf("control '%v' carries a reviewedOn date in the future: a review that has not happened is not a review (%s)", [control_id(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].reviewedOn", [i]),
	}
}

f_control_clock contains finding if {
	some i, c in control_rows
	not is_number(control_interval(c))
	finding := {
		"severity": "error",
		"rule": "control/interval-required",
		"message": sprintf("control '%v' declares no review clock (intervalDays): a control without a clock is a control nobody will ever re-review (%s)", [control_id(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].intervalDays", [i]),
	}
}

f_control_clock contains finding if {
	some i, c in control_rows
	is_number(control_interval(c))
	not is_positive_integer(control_interval(c))
	finding := {
		"severity": "error",
		"rule": "control/interval-invalid",
		"message": sprintf("control '%v' intervalDays must be a positive integer of days — the clock cannot count '%v' (%s)", [control_id(c), control_interval(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].intervalDays", [i]),
	}
}

f_control_dupes contains finding if {
	some c in control_rows
	lib.is_nonempty_string(control_id(c))
	count([d |
		some d in control_rows
		object.get(d, "id", null) == control_id(c)
	]) > 1
	finding := {
		"severity": "error",
		"rule": "control/id-duplicate",
		"message": sprintf("the control id '%v' is declared more than once: one id, one control — a control declared twice is evidence nobody can count (%s)", [control_id(c), controls_file]),
		"path": "$.controls.controls",
	}
}

# --- findings: the named evidence sources ----------------------------------------------

f_sources_array contains finding if {
	is_object(controls_doc)
	sources_field_present
	not is_array(object.get(controls_doc, "evidenceSources", null))
	finding := {
		"severity": "error",
		"rule": "sources/must-be-array",
		"message": sprintf("the manifest's evidenceSources field must be an array of source rows (%s)", [controls_file]),
		"path": "$.controls.evidenceSources",
	}
}

f_source_shape contains finding if {
	some i, s in as_array(controls_doc, "evidenceSources")
	not is_object(s)
	finding := {
		"severity": "error",
		"rule": "source/row-must-be-object",
		"message": sprintf("every evidence source must be an object: {id, kind, status} (%s)", [controls_file]),
		"path": sprintf("$.controls.evidenceSources[%d]", [i]),
	}
}

f_source_shape contains finding if {
	some i, s in source_rows
	not lib.is_nonempty_string(source_id(s))
	finding := {
		"severity": "error",
		"rule": "source/id-required",
		"message": sprintf("every evidence source needs an id: the controls cite it, and a source nobody can cite is a source nobody can audit (%s)", [controls_file]),
		"path": sprintf("$.controls.evidenceSources[%d].id", [i]),
	}
}

f_source_shape contains finding if {
	some i, s in source_rows
	not lib.is_nonempty_string(source_kind(s))
	finding := {
		"severity": "error",
		"rule": "source/kind-required",
		"message": sprintf("the evidence source '%v' must name its kind: what the source is tells the auditor where to look (%s)", [source_id(s), controls_file]),
		"path": sprintf("$.controls.evidenceSources[%d].kind", [i]),
	}
}

f_source_shape contains finding if {
	some i, s in source_rows
	not is_source_status(source_status(s))
	finding := {
		"severity": "error",
		"rule": "source/status-unknown",
		"message": sprintf("the evidence source '%v' carries status '%v': neither live nor retired — a source the manifest cannot place is a source nobody can cite (%s)", [source_id(s), source_status(s), controls_file]),
		"path": sprintf("$.controls.evidenceSources[%d].status", [i]),
	}
}

f_source_shape contains finding if {
	some s in source_rows
	lib.is_nonempty_string(source_id(s))
	count([d |
		some d in source_rows
		object.get(d, "id", null) == source_id(s)
	]) > 1
	finding := {
		"severity": "error",
		"rule": "source/id-duplicate",
		"message": sprintf("the evidence source id '%v' is declared more than once: one id, one source — a source declared twice is evidence nobody can count (%s)", [source_id(s), controls_file]),
		"path": "$.controls.evidenceSources",
	}
}

# --- findings: the citation join inside the manifest --------------------------------------

# A control citing an id the manifest never declares is a citation
# that resolves nowhere — the join the gate needs, judged here where
# citation and declaration live in the same document.
f_source_refs contains finding if {
	some i, c in control_rows
	lib.is_nonempty_string(control_evidence(c))
	not source_declared(control_evidence(c))
	finding := {
		"severity": "error",
		"rule": "control/evidence-source-unknown",
		"message": sprintf("control '%v' cites the evidence source '%v', but the manifest declares no such source: a citation that resolves nowhere is evidence nobody collects (%s)", [control_id(c), control_evidence(c), controls_file]),
		"path": sprintf("$.controls.controls[%d].evidenceSource", [i]),
	}
}

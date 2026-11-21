# The shared model for the compliance controls-as-data gate — The
# Software Field Guide, issue #107.
#
# Two documents enter: the CONTROLS MANIFEST (the estate's own word —
# the named evidence sources it collects, and every control with its
# title, owner, mapped requirements, evidence citation, and review
# clock) and the REQUIREMENTS CATALOG (compliance's answer — the
# requirements the estate must satisfy, each with its id, title, and
# source). One requirement, N controls: every catalog requirement
# must have a control mapped to it, and a mapped control is believed
# only while it cites evidence the estate still collects inside a
# review clock that has not lapsed. Every accessor here guards its
# input before touching object fields — a malformed document must
# produce findings, never a WASM trap.
package compliance

import rego.v1

import data.compliance.lib

# --- the input documents ------------------------------------------------------

controls_doc := v if {
	is_object(input)
	v := object.get(input, "controls", null)
}

controls_doc := null if not is_object(input)

requirements_doc := v if {
	is_object(input)
	v := object.get(input, "requirements", null)
}

requirements_doc := null if not is_object(input)

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
controls_file := v if {
	is_object(input)
	v := object.get(input, "controlsFile", "the controls manifest")
}

controls_file := "the controls manifest" if not is_object(input)

requirements_file := v if {
	is_object(input)
	v := object.get(input, "requirementsFile", "the requirements catalog")
}

requirements_file := "the requirements catalog" if not is_object(input)

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

# --- the controls manifest: the named evidence sources ---------------------------

source_rows := [s | some s in as_array(controls_doc, "evidenceSources"); is_object(s)]

source_id(s) := object.get(s, "id", null)

source_kind(s) := object.get(s, "kind", null)

source_status(s) := object.get(s, "status", null)

# The two states the manifest models. What a source actually contains
# is outside what a policy can check — the gate judges only that
# citations resolve and that retired sources are not still cited.
is_source_status(s) if s in {"live", "retired"}

source_declared(id) if {
	some s in source_rows
	lib.is_nonempty_string(source_id(s))
	source_id(s) == id
}

# The liveness join, judged row by row so a source declared twice (the
# validator's own finding) can never make the join ambiguous.
source_status_retired(id) if {
	some s in source_rows
	source_id(s) == id
	source_status(s) == "retired"
}

# The sources are readable when the field is absent (the manifest
# declares none) or an array — malformed rows are findings, and the
# joins judge the well-formed subset.
sources_field_present if {
	is_object(controls_doc)
	object.get(controls_doc, "evidenceSources", null) != null
}

sources_readable if not sources_field_present

sources_readable if {
	is_object(controls_doc)
	is_array(object.get(controls_doc, "evidenceSources", null))
}

# --- the controls manifest: the control rows ------------------------------------

control_rows := [c | some c in as_array(controls_doc, "controls"); is_object(c)]

control_id(c) := object.get(c, "id", null)

control_title(c) := object.get(c, "title", null)

control_owner(c) := object.get(c, "owner", null)

control_evidence(c) := object.get(c, "evidenceSource", null)

control_reviewed_on(c) := object.get(c, "reviewedOn", null)

control_interval(c) := object.get(c, "intervalDays", null)

# The requirement ids a control maps onto, as strings. Non-string
# entries are the validator's finding, never an ambiguity for the
# join — they are simply not mappings.
control_requirements(c) := [r | some r in as_array(c, "requirements"); is_string(r)]

# A control row a join can trust: an id to cite, a requirements array,
# a named evidence source, and a review clock the arithmetic can
# read. Titles and owners are the validator's findings, never an
# ambiguity for the join.
control_row_well_formed(c) if {
	is_object(c)
	lib.is_nonempty_string(control_id(c))
	is_array(object.get(c, "requirements", null))
	lib.is_nonempty_string(control_evidence(c))
	lib.is_valid_date(control_reviewed_on(c))
	is_positive_integer(control_interval(c))
}

well_formed_control_rows := [c | some c in control_rows; control_row_well_formed(c)]

# The controls are readable when every declared row is well-formed —
# a malformed row is the validator's finding, and the cards render
# only when the whole manifest can be asked.
controls_readable if {
	count(well_formed_control_rows) == count(as_array(controls_doc, "controls"))
}

# --- the review clock ------------------------------------------------------------

# The clock is judged with pure arithmetic: due = reviewedOn +
# intervalDays, and the control lapses the day after due — the
# boundary itself is inside the clock.
control_clock_expired(c) if {
	lib.is_valid_date(control_reviewed_on(c))
	is_positive_integer(control_interval(c))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) > lib.date_to_days(control_reviewed_on(c)) + control_interval(c)
}

# --- the requirements catalog ------------------------------------------------------

requirement_rows := [x | some x in as_array(requirements_doc, "requirements"); is_object(x)]

requirement_id(x) := object.get(x, "id", null)

requirement_row_well_formed(x) if {
	is_object(x)
	lib.is_nonempty_string(requirement_id(x))
}

# The catalog is readable when every declared row carries an id —
# a row without one is the gate's own finding, never an ambiguity
# for the join.
requirement_rows_readable if {
	count([x | some x in requirement_rows; requirement_row_well_formed(x)]) == count(requirement_rows)
}

# The declared requirements, sorted — the board the cards iterate,
# not the rows.
declared_requirements := sort({id |
	some x in requirement_rows
	requirement_row_well_formed(x)
	id := requirement_id(x)
})

requirement_declared(id) if {
	some r in declared_requirements
	r == id
}

# --- the join: one requirement, N controls ----------------------------------------

control_maps_to(c, req) if {
	some r in control_requirements(c)
	r == req
}

# The well-formed controls mapping onto one requirement, in document
# order.
controls_for(req) := [c |
	some c in well_formed_control_rows
	control_maps_to(c, req)
]

requirement_mapped(req) if {
	count(controls_for(req)) > 0
}

# A control the gate can believe: its review clock has not lapsed,
# and the evidence it cites is a declared source that is not retired.
control_gate_sound(c) if {
	control_row_well_formed(c)
	not control_clock_expired(c)
	source_declared(control_evidence(c))
	not source_status_retired(control_evidence(c))
}

# A requirement is covered when some mapped control is sound — the
# board renders the requirement, not the controls, so one sound
# control is the honest verdict.
requirement_covered(req) if {
	some c in controls_for(req)
	control_gate_sound(c)
}

# The sound and the problem controls mapped onto one requirement, in
# document order — the card cites the first of each, deterministically.
sound_controls_for(req) := [c | some c in controls_for(req); control_gate_sound(c)]

problem_controls_for(req) := [c | some c in controls_for(req); not control_gate_sound(c)]

first_sound_control(req) := c if {
	cs := sound_controls_for(req)
	count(cs) > 0
	c := cs[0]
}

first_problem_control(req) := c if {
	cs := problem_controls_for(req)
	count(cs) > 0
	c := cs[0]
}

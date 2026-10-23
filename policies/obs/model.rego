# The shared model for the observability contracts — The Software Field
# Guide, issue #61.
#
# Three documents enter: the event-name vocabulary, the metric label
# schema, and the cardinality budget (all versioned like code, each with
# a review date). Two artifacts are judged against them: a scan of the
# instrumentation code (telemetry calls with file:line evidence) and a
# metrics export (observed distinct values per metric+label). Every
# accessor here guards its input before touching object fields — a
# malformed document must produce findings, never a WASM trap.
package obs

import rego.v1

import data.obs.lib

# --- the input documents ------------------------------------------------------

vocab_doc := v if {
	is_object(input)
	v := object.get(input, "vocabulary", null)
}

vocab_doc := null if not is_object(input)

# The metric label schema arrives under the `labels` key.
schema_doc := v if {
	is_object(input)
	v := object.get(input, "labels", null)
}

schema_doc := null if not is_object(input)

budget_doc := v if {
	is_object(input)
	v := object.get(input, "budget", null)
}

budget_doc := null if not is_object(input)

scan_doc := v if {
	is_object(input)
	v := object.get(input, "scan", null)
}

scan_doc := null if not is_object(input)

# The budget file name is runner-supplied metadata: the policies cite it
# verbatim in messages so a CI log points back at the file that allocated
# the cardinality.
budget_file := f if {
	is_object(input)
	f := object.get(input, "budgetFile", "")
	is_string(f)
}

budget_file := "" if {
	is_object(input)
	not is_string(object.get(input, "budgetFile", ""))
}

budget_file := "" if not is_object(input)

# The optional citation suffix appended to budget findings: " (path.yaml)"
# when the runner named the file, "" when it did not.
budget_cite := sprintf(" (%s)", [budget_file]) if budget_file != ""

budget_cite := "" if budget_file == ""

# --- arrays, defensively ------------------------------------------------------

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

# --- numbers -------------------------------------------------------------------

is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

is_nonnegative_integer(v) if {
	is_number(v)
	v == floor(v)
	v >= 0
}

# --- vocabulary: the event-name catalogue ----------------------------------------

vocab_events := as_array(vocab_doc, "events")

event_objects := [e | some e in vocab_events; is_object(e)]

vocab_event_names := {object.get(e, "name", null) |
	some e in event_objects
	lib.is_nonempty_string(object.get(e, "name", null))
}

# --- label schema: metric → declared label set --------------------------------------

schema_metrics := [m | some m in as_array(schema_doc, "metrics"); is_object(m)]

schema_metric_names := {object.get(m, "name", null) |
	some m in schema_metrics
	lib.is_nonempty_string(object.get(m, "name", null))
}

# First schema metric carrying this name — duplicate names are the
# validator's finding, never an ambiguity for lookups.
schema_metric(name) := m if {
	matches := [m |
		some m in schema_metrics
		object.get(m, "name", null) == name
	]
	count(matches) > 0
	m := matches[0]
}

schema_metric_known(name) if schema_metric(name)

# The declared label set of a known metric.
declared_labels(name) := labels if {
	m := schema_metric(name)
	labels := {l |
		some l in as_array(m, "labels")
		lib.is_nonempty_string(l)
	}
}

# --- cardinality budget -----------------------------------------------------------

budget_metrics := [m | some m in as_array(budget_doc, "metrics"); is_object(m)]

budget_metric_names := {object.get(m, "name", null) |
	some m in budget_metrics
	lib.is_nonempty_string(object.get(m, "name", null))
}

budget_metric(name) := m if {
	matches := [m |
		some m in budget_metrics
		object.get(m, "name", null) == name
	]
	count(matches) > 0
	m := matches[0]
}

budget_metric_known(name) if budget_metric(name)

budget_total(name) := object.get(budget_metric(name), "total", null)

budget_allocations(name) := as_array(budget_metric(name), "allocations")

budget_allocation(name, label) := a if {
	matches := [a |
		some a in budget_allocations(name)
		is_object(a)
		object.get(a, "label", null) == label
	]
	count(matches) > 0
	a := matches[0]
}

budget_max_values(name, label) := object.get(budget_allocation(name, label), "maxValues", null)

# The position of a metric (or of an allocation inside a metric) in the
# budget document, so a finding can cite the exact allocation that bred
# the cardinality.
budget_metric_index(name) := i if {
	matches := [i |
		some i, m in budget_metrics
		object.get(m, "name", null) == name
	]
	count(matches) > 0
	i := matches[0]
}

budget_allocation_index(name, label) := i if {
	matches := [i |
		some i, a in budget_allocations(name)
		is_object(a)
		object.get(a, "label", null) == label
	]
	count(matches) > 0
	i := matches[0]
}

# --- the instrumentation scan -----------------------------------------------------

scan_calls := as_array(scan_doc, "calls")

call_kind(call) := object.get(call, "kind", null)

call_name(call) := object.get(call, "name", null)

call_file(call) := object.get(call, "file", null)

call_line(call) := object.get(call, "line", null)

call_labels(call) := object.get(call, "labels", [])

call_well_formed(call) if {
	is_object(call)
	call_kind(call) in {"event", "metric"}
	lib.is_nonempty_string(call_name(call))
	lib.is_nonempty_string(call_file(call))
	is_number(call_line(call))
	call_line(call) == floor(call_line(call))
	call_line(call) > 0
	is_array(call_labels(call))
	every l in call_labels(call) {
		lib.is_nonempty_string(l)
	}
}

# --- the metrics export: observed distinct values -------------------------------------

observation_rows := rows if {
	is_object(input)
	rows := object.get(input, "observations", [])
	is_array(rows)
}

observation_rows := [] if {
	is_object(input)
	not is_array(object.get(input, "observations", []))
}

observation_rows := [] if not is_object(input)

row_metric(row) := object.get(row, "metric", null)

row_label(row) := object.get(row, "label", null)

row_distinct(row) := object.get(row, "distinct", null)

row_well_formed(row) if {
	is_object(row)
	lib.is_nonempty_string(row_metric(row))
	lib.is_nonempty_string(row_label(row))
	is_positive_integer(row_distinct(row))
}

# Distinct values observed for one metric+label. A repeated row can only
# overstate reality, so the export's maximum is taken, never averaged.
observed_distinct(metric, label) := d if {
	values := [row_distinct(r) |
		some r in observation_rows
		row_well_formed(r)
		row_metric(r) == metric
		row_label(r) == label
	]
	count(values) > 0
	d := max(values)
}

observed_metrics := {row_metric(r) |
	some r in observation_rows
	row_well_formed(r)
}

observed_labels(metric) := {row_label(r) |
	some r in observation_rows
	row_well_formed(r)
	row_metric(r) == metric
}

# The label combinations a metric would carry from its observed distinct
# values — the honest product of what the export actually shows.
observed_product(metric) := product([observed_distinct(metric, l) |
	some l in observed_labels(metric)
])

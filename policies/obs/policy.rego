# Observability contract validator — The Software Field Guide, issue #61.
#
# Judges the three contract documents on their own: the event-name
# vocabulary, the metric label schema, and the cardinality budget. Both
# vocabularies are versioned like code, so each carries a version stamp
# and a review date; the budget additionally carries an owner (the
# chapter: a budget with an owner and a review cadence). Cross-checks
# run between schema and budget: a budget for an unknown metric, an
# allocation for a label the schema never declared, a schema label the
# budget never allocated, and a total smaller than the allocations'
# own product — the static version of the cardinality lie.
#
# Input (JSON): {"vocabulary": {...}, "labels": {...}, "budget": {...},
#                "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [{severity, rule, message, path}]}
package obs

import rego.v1

import data.obs.lib

# --- entrypoint -------------------------------------------------------------

validate := result if {
	fs := sort([f | some f in validate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
	}
}

validate_findings := (((((((f_input_invalid | f_today_invalid) | f_doc_missing) | f_version) | f_reviewed) | f_vocab_content) | f_schema_content) | f_budget_content) | f_budget_cross

f_doc_missing := (f_vocab_missing | f_schema_missing) | f_budget_missing

# --- findings: input shape -----------------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with vocabulary, labels, and budget documents",
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

# --- findings: a document is missing ----------------------------------------------

f_vocab_missing contains finding if {
	not is_object(vocab_doc)
	finding := {
		"severity": "error",
		"rule": "vocab/missing",
		"message": "the event-name vocabulary is required: pass it as input.vocabulary",
		"path": "$.vocabulary",
	}
}

f_schema_missing contains finding if {
	not is_object(schema_doc)
	finding := {
		"severity": "error",
		"rule": "schema/missing",
		"message": "the metric label schema is required: pass it as input.labels",
		"path": "$.labels",
	}
}

f_budget_missing contains finding if {
	not is_object(budget_doc)
	finding := {
		"severity": "error",
		"rule": "budget/missing",
		"message": "the cardinality budget is required: pass it as input.budget",
		"path": "$.budget",
	}
}

# --- findings: version and review stamps -------------------------------------------

# The version and review stamps are per-document; the descriptor lists
# below let one finding rule judge all documents the same way.

# Both vocabularies are versioned like code; the budget carries the
# owner and the review cadence instead.
versioned_docs := [
	{
		"doc": vocab_doc,
		"prefix": "vocab",
		"what": "the event-name vocabulary",
		"path": "$.vocabulary",
	},
	{
		"doc": schema_doc,
		"prefix": "schema",
		"what": "the metric label schema",
		"path": "$.labels",
	},
]

reviewed_docs := array.concat(versioned_docs, [{
	"doc": budget_doc,
	"prefix": "budget",
	"what": "the cardinality budget",
	"path": "$.budget",
}])

f_version contains finding if {
	some d in versioned_docs
	is_object(d.doc)
	not is_positive_integer(object.get(d.doc, "version", null))
	finding := {
		"severity": "error",
		"rule": sprintf("%s/version-required", [d.prefix]),
		"message": sprintf("%s must carry a version (a positive integer): the vocabularies are versioned like code", [d.what]),
		"path": sprintf("%s.version", [d.path]),
	}
}

f_reviewed contains finding if {
	some d in reviewed_docs
	is_object(d.doc)
	not lib.is_valid_date(object.get(d.doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": sprintf("%s/reviewed-on-invalid", [d.prefix]),
		"message": sprintf("%s must carry reviewedOn as a real YYYY-MM-DD date", [d.what]),
		"path": sprintf("%s.reviewedOn", [d.path]),
	}
}

f_reviewed contains finding if {
	some d in reviewed_docs
	is_object(d.doc)
	lib.is_valid_date(object.get(d.doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(d.doc, "reviewedOn", null)) > lib.date_to_days(object.get(input, "today", null))
	finding := {
		"severity": "error",
		"rule": sprintf("%s/reviewed-in-future", [d.prefix]),
		"message": sprintf("%s carries a reviewedOn date in the future", [d.what]),
		"path": sprintf("%s.reviewedOn", [d.path]),
	}
}

f_reviewed contains finding if {
	some d in reviewed_docs
	is_object(d.doc)
	lib.is_valid_date(object.get(d.doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(input, "today", null)) - lib.date_to_days(object.get(d.doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": sprintf("%s/reviewed-stale", [d.prefix]),
		"message": sprintf("%s was reviewed more than 365 days before today: this document is stale", [d.what]),
		"path": sprintf("%s.reviewedOn", [d.path]),
	}
}

# --- findings: vocabulary content -----------------------------------------------------

f_vocab_content := f_vocab_events

f_vocab_events contains finding if {
	is_object(vocab_doc)
	not is_array(object.get(vocab_doc, "events", null))
	finding := {
		"severity": "error",
		"rule": "vocab/events-must-be-array",
		"message": "events must be an array of {name, description} entries",
		"path": "$.vocabulary.events",
	}
}

f_vocab_events contains finding if {
	is_object(vocab_doc)
	is_array(object.get(vocab_doc, "events", null))
	count(vocab_events) == 0
	finding := {
		"severity": "error",
		"rule": "vocab/events-required",
		"message": "the vocabulary must declare at least one event name: 'which event names exist?' must be a queryable fact",
		"path": "$.vocabulary.events",
	}
}

f_vocab_events contains finding if {
	some i, e in vocab_events
	not is_object(e)
	finding := {
		"severity": "error",
		"rule": "vocab/event-must-be-object",
		"message": sprintf("event entry %d must be an object with name and description", [i]),
		"path": sprintf("$.vocabulary.events[%d]", [i]),
	}
}

f_vocab_events contains finding if {
	some i, e in vocab_events
	is_object(e)
	not lib.is_nonempty_string(object.get(e, "name", null))
	finding := {
		"severity": "error",
		"rule": "vocab/event-name-required",
		"message": sprintf("event entry %d must carry a non-empty name", [i]),
		"path": sprintf("$.vocabulary.events[%d].name", [i]),
	}
}

f_vocab_events contains finding if {
	some i, e in vocab_events
	is_object(e)
	lib.is_nonempty_string(object.get(e, "name", null))
	not lib.is_nonempty_string(object.get(e, "description", null))
	finding := {
		"severity": "error",
		"rule": "vocab/event-description-required",
		"message": sprintf("event entry %d ('%s') must carry a non-empty description", [i, object.get(e, "name", null)]),
		"path": sprintf("$.vocabulary.events[%d].description", [i]),
	}
}

f_vocab_events contains finding if {
	names := [object.get(e, "name", null) |
		some e in event_objects
		lib.is_nonempty_string(object.get(e, "name", null))
	]
	some name in names
	count([n | some n in names; n == name]) > 1
	finding := {
		"severity": "error",
		"rule": "vocab/event-name-duplicate",
		"message": sprintf("event name '%s' appears more than once in the vocabulary", [name]),
		"path": "$.vocabulary.events",
	}
}

# --- findings: label schema content ------------------------------------------------------

f_schema_content := f_schema_metrics

f_schema_metrics contains finding if {
	is_object(schema_doc)
	not is_array(object.get(schema_doc, "metrics", null))
	finding := {
		"severity": "error",
		"rule": "schema/metrics-must-be-array",
		"message": "metrics must be an array of {name, description, labels} entries",
		"path": "$.labels.metrics",
	}
}

f_schema_metrics contains finding if {
	is_object(schema_doc)
	is_array(object.get(schema_doc, "metrics", null))
	count(schema_metrics) == 0
	finding := {
		"severity": "error",
		"rule": "schema/metrics-required",
		"message": "the label schema must declare at least one metric",
		"path": "$.labels.metrics",
	}
}

f_schema_metrics contains finding if {
	some i, m in as_array(schema_doc, "metrics")
	not is_object(m)
	finding := {
		"severity": "error",
		"rule": "schema/metric-must-be-object",
		"message": sprintf("metric entry %d must be an object with name, description, and labels", [i]),
		"path": sprintf("$.labels.metrics[%d]", [i]),
	}
}

f_schema_metrics contains finding if {
	some i, m in schema_metrics
	not lib.is_nonempty_string(object.get(m, "name", null))
	finding := {
		"severity": "error",
		"rule": "schema/metric-name-required",
		"message": sprintf("metric entry %d must carry a non-empty name", [i]),
		"path": sprintf("$.labels.metrics[%d].name", [i]),
	}
}

f_schema_metrics contains finding if {
	names := [object.get(m, "name", null) |
		some m in schema_metrics
		lib.is_nonempty_string(object.get(m, "name", null))
	]
	some name in names
	count([n | some n in names; n == name]) > 1
	finding := {
		"severity": "error",
		"rule": "schema/metric-name-duplicate",
		"message": sprintf("metric name '%s' appears more than once in the label schema", [name]),
		"path": "$.labels.metrics",
	}
}

# The label list is the contract: it must be declared explicitly, even
# when empty — an unlabeled metric is a legitimate contract, a silent
# one is not.
f_schema_metrics contains finding if {
	some i, m in schema_metrics
	not is_array(object.get(m, "labels", null))
	finding := {
		"severity": "error",
		"rule": "schema/metric-labels-must-be-array",
		"message": sprintf("metric '%s' must declare its label set as an array (an empty array is a valid contract)", [object.get(m, "name", "unnamed")]),
		"path": sprintf("$.labels.metrics[%d].labels", [i]),
	}
}

f_schema_metrics contains finding if {
	some i, m in schema_metrics
	some j, l in as_array(m, "labels")
	not lib.is_nonempty_string(l)
	finding := {
		"severity": "error",
		"rule": "schema/metric-label-required",
		"message": sprintf("metric '%s' declares a non-string label at position %d", [object.get(m, "name", "unnamed"), j]),
		"path": sprintf("$.labels.metrics[%d].labels[%d]", [i, j]),
	}
}

f_schema_metrics contains finding if {
	some i, m in as_array(schema_doc, "metrics")
	is_object(m)
	labels := as_array(m, "labels")
	some l in labels
	count([x | some x in labels; x == l]) > 1
	finding := {
		"severity": "error",
		"rule": "schema/metric-label-duplicate",
		"message": sprintf("label '%s' appears more than once in the label set of metric '%s'", [l, object.get(m, "name", "unnamed")]),
		"path": sprintf("$.labels.metrics[%d].labels", [i]),
	}
}

# --- findings: budget content ---------------------------------------------------------------

f_budget_content := f_budget_owner | f_budget_metrics

f_budget_owner contains finding if {
	is_object(budget_doc)
	not lib.is_nonempty_string(object.get(budget_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "budget/owner-required",
		"message": "the cardinality budget must name an owner: a budget with an owner and a review cadence is the discipline",
		"path": "$.budget.owner",
	}
}

f_budget_metrics contains finding if {
	is_object(budget_doc)
	not is_array(object.get(budget_doc, "metrics", null))
	finding := {
		"severity": "error",
		"rule": "budget/metrics-must-be-array",
		"message": "metrics must be an array of {name, total, allocations} entries",
		"path": "$.budget.metrics",
	}
}

f_budget_metrics contains finding if {
	is_object(budget_doc)
	is_array(object.get(budget_doc, "metrics", null))
	count(budget_metrics) == 0
	finding := {
		"severity": "error",
		"rule": "budget/metrics-required",
		"message": "the cardinality budget must state at least one metric",
		"path": "$.budget.metrics",
	}
}

f_budget_metrics contains finding if {
	some i, m in as_array(budget_doc, "metrics")
	not is_object(m)
	finding := {
		"severity": "error",
		"rule": "budget/metric-must-be-object",
		"message": sprintf("budget metric entry %d must be an object with name, total, and allocations", [i]),
		"path": sprintf("$.budget.metrics[%d]", [i]),
	}
}

f_budget_metrics contains finding if {
	some i, m in budget_metrics
	not lib.is_nonempty_string(object.get(m, "name", null))
	finding := {
		"severity": "error",
		"rule": "budget/metric-name-required",
		"message": sprintf("budget metric entry %d must carry a non-empty name", [i]),
		"path": sprintf("$.budget.metrics[%d].name", [i]),
	}
}

f_budget_metrics contains finding if {
	names := [object.get(m, "name", null) |
		some m in budget_metrics
		lib.is_nonempty_string(object.get(m, "name", null))
	]
	some name in names
	count([n | some n in names; n == name]) > 1
	finding := {
		"severity": "error",
		"rule": "budget/metric-name-duplicate",
		"message": sprintf("metric name '%s' appears more than once in the cardinality budget", [name]),
		"path": "$.budget.metrics",
	}
}

f_budget_metrics contains finding if {
	some i, m in budget_metrics
	not is_positive_integer(object.get(m, "total", null))
	finding := {
		"severity": "error",
		"rule": "budget/metric-total-required",
		"message": sprintf("budget metric '%s' must state a total (a positive integer): the ceiling on label combinations", [object.get(m, "name", "unnamed")]),
		"path": sprintf("$.budget.metrics[%d].total", [i]),
	}
}

f_budget_metrics contains finding if {
	some i, m in budget_metrics
	not is_array(object.get(m, "allocations", null))
	finding := {
		"severity": "error",
		"rule": "budget/allocations-must-be-array",
		"message": sprintf("budget metric '%s' must state its per-label allocations as an array (an empty array is valid for an unlabeled metric)", [object.get(m, "name", "unnamed")]),
		"path": sprintf("$.budget.metrics[%d].allocations", [i]),
	}
}

f_budget_metrics contains finding if {
	some i, m in budget_metrics
	some j, a in as_array(m, "allocations")
	not is_object(a)
	finding := {
		"severity": "error",
		"rule": "budget/allocation-must-be-object",
		"message": sprintf("allocation %d of budget metric '%s' must be an object with label and maxValues", [j, object.get(m, "name", "unnamed")]),
		"path": sprintf("$.budget.metrics[%d].allocations[%d]", [i, j]),
	}
}

f_budget_metrics contains finding if {
	some i, m in budget_metrics
	some j, a in as_array(m, "allocations")
	is_object(a)
	not lib.is_nonempty_string(object.get(a, "label", null))
	finding := {
		"severity": "error",
		"rule": "budget/allocation-label-required",
		"message": sprintf("allocation %d of budget metric '%s' must carry a non-empty label", [j, object.get(m, "name", "unnamed")]),
		"path": sprintf("$.budget.metrics[%d].allocations[%d].label", [i, j]),
	}
}

f_budget_metrics contains finding if {
	some i, m in budget_metrics
	some j, a in as_array(m, "allocations")
	is_object(a)
	lib.is_nonempty_string(object.get(a, "label", null))
	not is_positive_integer(object.get(a, "maxValues", null))
	finding := {
		"severity": "error",
		"rule": "budget/allocation-maxvalues-required",
		"message": sprintf("allocation for label '%s' of budget metric '%s' must state maxValues as a positive integer", [object.get(a, "label", null), object.get(m, "name", "unnamed")]),
		"path": sprintf("$.budget.metrics[%d].allocations[%d].maxValues", [i, j]),
	}
}

f_budget_metrics contains finding if {
	some i, m in as_array(budget_doc, "metrics")
	is_object(m)
	allocations := [a |
		some a in as_array(m, "allocations")
		is_object(a)
		lib.is_nonempty_string(object.get(a, "label", null))
	]
	some a in allocations
	count([x | some x in allocations; object.get(x, "label", null) == object.get(a, "label", null)]) > 1
	finding := {
		"severity": "error",
		"rule": "budget/allocation-label-duplicate",
		"message": sprintf("label '%s' is allocated more than once in budget metric '%s'", [object.get(a, "label", null), object.get(m, "name", "unnamed")]),
		"path": sprintf("$.budget.metrics[%d].allocations", [i]),
	}
}

# --- findings: budget ↔ schema cross-checks ------------------------------------------------------

f_budget_cross contains finding if {
	is_object(schema_doc)
	some i, m in budget_metrics
	lib.is_nonempty_string(object.get(m, "name", null))
	not schema_metric_known(object.get(m, "name", null))
	finding := {
		"severity": "error",
		"rule": "budget/metric-unknown",
		"message": sprintf("budget metric '%s' is not declared in the label schema: the two documents disagree", [object.get(m, "name", null)]),
		"path": sprintf("$.budget.metrics[%d].name", [i]),
	}
}

f_budget_cross contains finding if {
	is_object(schema_doc)
	some m in budget_metrics
	name := object.get(m, "name", null)
	schema_metric_known(name)
	some a in as_array(m, "allocations")
	is_object(a)
	lib.is_nonempty_string(object.get(a, "label", null))
	not object.get(a, "label", null) in declared_labels(name)
	finding := {
		"severity": "error",
		"rule": "budget/allocation-label-unknown",
		"message": sprintf("budget metric '%s' allocates cardinality for label '%s', which the label schema never declared", [name, object.get(a, "label", null)]),
		"path": sprintf("$.budget.metrics[%d].allocations[%d].label", [budget_metric_index(name), budget_allocation_index(name, object.get(a, "label", null))]),
	}
}

f_budget_cross contains finding if {
	is_object(schema_doc)
	some m in schema_metrics
	name := object.get(m, "name", null)
	schema_metric_known(name)
	budget_metric_known(name)
	some l in declared_labels(name)
	not budget_allocation(name, l)
	finding := {
		"severity": "error",
		"rule": "budget/schema-label-unallocated",
		"message": sprintf("the label schema declares label '%s' on metric '%s', but the cardinality budget allocates nothing for it: its cardinality is unbudgeted", [l, name]),
		"path": sprintf("$.budget.metrics[%d].allocations", [budget_metric_index(name)]),
	}
}

# The static version of the cardinality lie: the allocations themselves
# multiply past the total, before any export is consulted.
f_budget_cross contains finding if {
	some m in budget_metrics
	name := object.get(m, "name", null)
	is_positive_integer(object.get(m, "total", null))
	maxes := [object.get(a, "maxValues", null) |
		some a in as_array(m, "allocations")
		is_object(a)
		is_positive_integer(object.get(a, "maxValues", null))
	]
	count(maxes) > 0
	product(maxes) > object.get(m, "total", null)
	finding := {
		"severity": "error",
		"rule": "budget/total-below-allocations",
		"message": sprintf("the allocations of budget metric '%s' multiply to %d label combinations, past its own total of %d", [name, product(maxes), object.get(m, "total", null)]),
		"path": sprintf("$.budget.metrics[%d]", [budget_metric_index(name)]),
	}
}

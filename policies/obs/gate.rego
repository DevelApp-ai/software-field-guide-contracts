# Cardinality gate — The Software Field Guide, issue #61.
#
# Compares the metrics export (observed distinct values per metric+label)
# against the cardinality budget. The chapter's promise: a pull request
# that adds an unbounded label to a metric is a review comment, not a
# discovery in a 3 a.m. page. Three ways to breach the budget, each with
# the budget document cited: a label observed past its allocation
# (budget/label-over-allocation), a label observed with no allocation at
# all (budget/label-unallocated), and the honest product of observed
# distinct values past the metric's total (budget/metric-total-exceeded).
#
# Input (JSON): {"labels": {...}, "budget": {...},
#                "observations": [{"metric", "label", "distinct"}],
#                "budgetFile": "path/to/cardinality-budget.yaml" (optional)}
# Result:       {"valid": bool, "findings": [...], "cardinalities": [...]}
package obs

import rego.v1

import data.obs.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"cardinalities": cardinalities,
	}
}

gate_findings := ((((f_input_invalid | f_schema_missing) | f_budget_missing) | f_observations_missing) | f_gate_rows) | f_gate

# --- findings: the export must be readable --------------------------------------------

f_observations_missing contains finding if {
	is_object(input)
	not is_array(object.get(input, "observations", null))
	finding := {
		"severity": "error",
		"rule": "gate/observations-missing",
		"message": "the metrics export is required: pass observations as an array of {metric, label, distinct} rows",
		"path": "$.observations",
	}
}

f_gate_rows contains finding if {
	some i, row in observation_rows
	not row_well_formed(row)
	finding := {
		"severity": "error",
		"rule": "gate/observation-row-invalid",
		"message": sprintf("observation row %d must carry metric (non-empty string), label (non-empty string), and distinct (a positive integer)", [i]),
		"path": sprintf("$.observations[%d]", [i]),
	}
}

# --- findings: the budget, breached ------------------------------------------------------

f_gate contains finding if {
	some i, row in observation_rows
	row_well_formed(row)
	not budget_metric_known(row_metric(row))
	finding := {
		"severity": "error",
		"rule": "budget/metric-unallocated",
		"message": sprintf("metric '%s' carries observed label values but has no entry in the cardinality budget%s", [row_metric(row), budget_cite]),
		"path": sprintf("$.observations[%d]", [i]),
	}
}

f_gate contains finding if {
	some i, row in observation_rows
	row_well_formed(row)
	budget_metric_known(row_metric(row))
	not budget_allocation(row_metric(row), row_label(row))
	finding := {
		"severity": "error",
		"rule": "budget/label-unallocated",
		"message": sprintf("label '%s' on metric '%s' carries observed values but has no allocation in the cardinality budget: its cardinality is unbudgeted%s", [row_label(row), row_metric(row), budget_cite]),
		"path": sprintf("$.observations[%d]", [i]),
	}
}

f_gate contains finding if {
	is_object(schema_doc)
	some i, row in observation_rows
	row_well_formed(row)
	schema_metric_known(row_metric(row))
	not row_label(row) in declared_labels(row_metric(row))
	finding := {
		"severity": "error",
		"rule": "gate/label-undeclared",
		"message": sprintf("label '%s' on metric '%s' shows observed values but is not in the metric's label schema: the schema and the registry disagree", [row_label(row), row_metric(row)]),
		"path": sprintf("$.observations[%d]", [i]),
	}
}

# The budget-breeding label, caught: the export shows more distinct
# values than the allocation permits, and the finding points at the
# exact allocation in the budget document.
f_gate contains finding if {
	some row in observation_rows
	row_well_formed(row)
	budget_allocation(row_metric(row), row_label(row))
	is_positive_integer(budget_max_values(row_metric(row), row_label(row)))
	observed_distinct(row_metric(row), row_label(row)) > budget_max_values(row_metric(row), row_label(row))
	finding := {
		"severity": "error",
		"rule": "budget/label-over-allocation",
		"message": sprintf("label '%s' on metric '%s' shows %d distinct values in the metrics export; the cardinality budget allocates %d%s", [
			row_label(row),
			row_metric(row),
			observed_distinct(row_metric(row), row_label(row)),
			budget_max_values(row_metric(row), row_label(row)),
			budget_cite,
		]),
		"path": sprintf("$.budget.metrics[%d].allocations[%d]", [
			budget_metric_index(row_metric(row)),
			budget_allocation_index(row_metric(row), row_label(row)),
		]),
	}
}

# The metric as a whole: the honest product of observed distinct values
# against the budget's ceiling on label combinations.
f_gate contains finding if {
	some metric in observed_metrics
	budget_metric_known(metric)
	is_positive_integer(budget_total(metric))
	observed_product(metric) > budget_total(metric)
	finding := {
		"severity": "error",
		"rule": "budget/metric-total-exceeded",
		"message": sprintf("metric '%s' multiplies observed distinct values to %d label combinations; the cardinality budget total is %d%s", [
			metric,
			observed_product(metric),
			budget_total(metric),
			budget_cite,
		]),
		"path": sprintf("$.budget.metrics[%d]", [budget_metric_index(metric)]),
	}
}

# --- cardinalities: what the export actually shows ----------------------------------------

# Per metric: each observed label's distinct values, and the product —
# the label combinations the metric would carry. Sorted for determinism.
cardinalities := sort([{
	"metric": metric,
	"labels": sort([{
		"label": l,
		"distinct": observed_distinct(metric, l),
	} |
		some l in observed_labels(metric)
	]),
	"product": observed_product(metric),
} |
	some metric in observed_metrics
])

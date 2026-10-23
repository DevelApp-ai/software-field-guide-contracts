package obs.gate_test

import rego.v1

import data.obs

import data.obs.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

gate_input(observations) := {
	"labels": fixture.label_schema,
	"budget": fixture.budget,
	"observations": observations,
	"budgetFile": "examples/observability/cardinality-budget.yaml",
}

test_good_export_passes if {
	r := obs.gate with input as gate_input(fixture.good_observations)
	r.valid == true
	count(r.findings) == 0
}

test_cardinalities_report_the_honest_product if {
	r := obs.gate with input as gate_input(fixture.good_observations)
	count(r.cardinalities) == 2
	c := r.cardinalities[0]
	c.metric == "storefront_requests_total"
	c.product == 148
	count(c.labels) == 3
	c.labels[0] == {"label": "method", "distinct": 2}
}

test_budget_breeding_label_is_caught_with_the_budget_cited if {
	# the done-when: order_id shows 1204 distinct values, the budget
	# allocated 50, and the finding points at the allocation
	gate_in := {
		"labels": fixture.breach_schema,
		"budget": fixture.breach_budget,
		"observations": fixture.breach_observations,
		"budgetFile": "cardinality-budget.yaml",
	}
	r := obs.gate with input as gate_in
	not r.valid
	some f in r.findings
	f.rule == "budget/label-over-allocation"
	contains(f.message, "shows 1204 distinct values")
	contains(f.message, "allocates 50 (cardinality-budget.yaml)")
	f.path == "$.budget.metrics[0].allocations[3]"
}

test_metric_total_exceeded if {
	gate_in := {
		"labels": fixture.breach_schema,
		"budget": fixture.breach_budget,
		"observations": fixture.breach_observations,
		"budgetFile": "cardinality-budget.yaml",
	}
	r := obs.gate with input as gate_in
	not r.valid
	some f in r.findings
	f.rule == "budget/metric-total-exceeded"
	contains(f.message, "multiplies observed distinct values to 178192 label combinations")
	contains(f.message, "total is 4000 (cardinality-budget.yaml)")
	f.path == "$.budget.metrics[0]"
}

test_breach_produces_exactly_the_two_budget_findings if {
	# the schema was updated and the budget allocated: no other rule may
	# fire — the mechanism-exact bite
	gate_in := {
		"labels": fixture.breach_schema,
		"budget": fixture.breach_budget,
		"observations": fixture.breach_observations,
	}
	r := obs.gate with input as gate_in
	not r.valid
	count(r.findings) == 2
}

test_label_unallocated if {
	rows := array.concat(fixture.good_observations, [fixture.obs_row("storefront_requests_total", "tenant", 3)])
	r := obs.gate with input as gate_input(rows)
	not r.valid
	some f in r.findings
	f.rule == "budget/label-unallocated"
	contains(f.message, "label 'tenant' on metric 'storefront_requests_total'")
	f.path == "$.observations[5]"
}

test_metric_unallocated if {
	rows := array.concat(fixture.good_observations, [fixture.obs_row("carts_total", "tenant", 3)])
	r := obs.gate with input as gate_input(rows)
	not r.valid
	some f in r.findings
	f.rule == "budget/metric-unallocated"
	contains(f.message, "metric 'carts_total' carries observed label values but has no entry in the cardinality budget")
}

test_label_undeclared_from_the_export if {
	# the schema and the registry disagree: the export shows a label the
	# schema never declared
	rows := array.concat(fixture.good_observations, [fixture.obs_row("payment_settlements_total", "order_id", 9)])
	r := obs.gate with input as gate_input(rows)
	not r.valid
	some f in r.findings
	f.rule == "gate/label-undeclared"
	contains(f.message, "label 'order_id' on metric 'payment_settlements_total'")
}

test_observations_missing if {
	r := obs.gate with input as {"labels": fixture.label_schema, "budget": fixture.budget}
	not r.valid
	error_rules(r)["gate/observations-missing"]
}

test_observations_must_be_array if {
	r := obs.gate with input as object.union(gate_input(fixture.good_observations), {"observations": {"rows": []}})
	not r.valid
	error_rules(r)["gate/observations-missing"]
}

test_observation_row_invalid if {
	rows := array.concat(fixture.good_observations, [{"metric": "carts_total", "label": "tenant", "distinct": "many"}])
	r := obs.gate with input as gate_input(rows)
	not r.valid
	some f in r.findings
	f.rule == "gate/observation-row-invalid"
	f.path == "$.observations[5]"
}

test_repeated_rows_overstate_never_understate if {
	rows := array.concat(fixture.good_observations, [fixture.obs_row("storefront_requests_total", "status", 50)])
	r := obs.gate with input as gate_input(rows)
	r.valid == true
	some c in r.cardinalities
	c.metric == "storefront_requests_total"
	c.product == 200
}

test_gate_requires_the_budget if {
	r := obs.gate with input as {"labels": fixture.label_schema, "observations": fixture.good_observations}
	not r.valid
	error_rules(r)["budget/missing"]
}

test_input_must_be_object if {
	r := obs.gate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

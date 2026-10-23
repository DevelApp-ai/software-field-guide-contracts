package obs.audit_test

import rego.v1

import data.obs

import data.obs.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

good_audit_input := {
	"vocabulary": fixture.vocabulary,
	"labels": fixture.label_schema,
	"budget": fixture.budget,
	"today": fixture.today,
	"scan": fixture.good_scan,
	"observations": fixture.good_observations,
}

test_good_audit_passes if {
	r := obs.audit with input as good_audit_input
	r.valid == true
	count(r.findings) == 0
	count(r.cardinalities) == 2
}

test_audit_composes_all_three_analyzers if {
	# one broken scan row, one unbudgeted export row, and a stale budget
	# review — all three analyzers answer in one evaluation
	audit_in := object.union(good_audit_input, {
		"scan": {"calls": array.concat(fixture.good_scan.calls, [
			fixture.metric_call("src/storefront.py", 30, "carts_total", ["tenant"]),
		])},
		"observations": array.concat(fixture.good_observations, [
			fixture.obs_row("storefront_requests_total", "session_id", 800),
		]),
		"budget": object.union(fixture.budget, {"reviewedOn": "2025-09-01"}),
	})
	r := obs.audit with input as audit_in
	not r.valid
	error_rules(r)["lint/metric-undeclared"]
	error_rules(r)["budget/label-unallocated"]
	error_rules(r)["budget/reviewed-stale"]
}

test_missing_documents_reported_once_each if {
	# findings are sets: a condition shared by analyzers is reported once
	r := obs.audit with input as {"today": fixture.today}
	not r.valid
	count([f | some f in r.findings; f.rule == "vocab/missing"]) == 1
	count([f | some f in r.findings; f.rule == "schema/missing"]) == 1
	count([f | some f in r.findings; f.rule == "budget/missing"]) == 1
	count([f | some f in r.findings; f.rule == "scan/missing"]) == 1
	count([f | some f in r.findings; f.rule == "gate/observations-missing"]) == 1
}

test_missing_today_is_a_finding if {
	no_today := object.remove(good_audit_input, ["today"])
	r := obs.audit with input as no_today
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_input_must_be_object if {
	r := obs.audit with input as [1, 2]
	not r.valid
	count([f | some f in r.findings; f.rule == "input/invalid"]) == 1
}

test_audit_and_gate_agree_on_cardinalities if {
	g := obs.gate with input as {
		"labels": fixture.label_schema,
		"budget": fixture.budget,
		"observations": fixture.good_observations,
	}
	a := obs.audit with input as good_audit_input
	g.cardinalities == a.cardinalities
}

test_audit_catches_the_done_when_breach if {
	# the composed verdict carries the budget-breeding label with the
	# budget file cited — the exact answer the demo CI run asserts
	done_when_input := {
		"vocabulary": fixture.vocabulary,
		"labels": fixture.breach_schema,
		"budget": fixture.breach_budget,
		"today": fixture.today,
		"scan": fixture.good_scan,
		"observations": fixture.breach_observations,
		"budgetFile": "cardinality-budget.yaml",
	}
	r := obs.audit with input as done_when_input
	not r.valid
	some f in r.findings
	f.rule == "budget/label-over-allocation"
	contains(f.message, "(cardinality-budget.yaml)")
}

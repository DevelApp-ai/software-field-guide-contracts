package obs.policy_test

import rego.v1

import data.obs

import data.obs.fixture

import data.obs.lib

today := fixture.today

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- input shape --------------------------------------------------------------

test_valid_contracts_pass if {
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	r.valid == true
	count(r.findings) == 0
}

test_input_must_be_object if {
	r := obs.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": fixture.budget, "today": "yesterday"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_today_missing if {
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": fixture.budget}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

# --- missing documents ----------------------------------------------------------

test_vocab_missing if {
	r := obs.validate with input as {"labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["vocab/missing"]
}

test_schema_missing if {
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["schema/missing"]
}

test_budget_missing if {
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "today": today}
	not r.valid
	error_rules(r)["budget/missing"]
}

# --- version stamps ---------------------------------------------------------------

test_vocab_version_missing if {
	v := object.remove(fixture.vocabulary, ["version"])
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["vocab/version-required"]
}

test_schema_version_not_positive if {
	s := object.union(fixture.label_schema, {"version": 0})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": s, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["schema/version-required"]
}

test_budget_has_no_version_stamp if {
	# the budget carries owner and reviewedOn instead of a version
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not error_rules(r)["budget/version-required"]
}

# --- review dates --------------------------------------------------------------------

test_reviewed_on_invalid if {
	v := object.union(fixture.vocabulary, {"reviewedOn": "2026-2-30"})
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["vocab/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	v := object.union(fixture.vocabulary, {"reviewedOn": "2026-10-21"})
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["vocab/reviewed-in-future"]
}

test_reviewed_stale if {
	v := object.union(fixture.vocabulary, {"reviewedOn": "2025-10-19"})
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["vocab/reviewed-stale"]
}

test_reviewed_exactly_365_days_old_passes if {
	v := object.union(fixture.vocabulary, {"reviewedOn": "2025-10-20"})
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	r.valid == true
}

test_budget_reviewed_stale if {
	b := object.union(fixture.budget, {"reviewedOn": "2025-10-01"})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": b, "today": today}
	not r.valid
	error_rules(r)["budget/reviewed-stale"]
}

# --- vocabulary content -----------------------------------------------------------------

test_events_must_be_array if {
	v := object.remove(fixture.vocabulary, ["events"])
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["vocab/events-must-be-array"]
}

test_events_required if {
	v := object.union(fixture.vocabulary, {"events": []})
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["vocab/events-required"]
}

test_event_name_required if {
	v := object.union(fixture.vocabulary, {"events": [{"name": "", "description": "no name"}]})
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	some f in r.findings
	f.rule == "vocab/event-name-required"
	f.path == "$.vocabulary.events[0].name"
}

test_event_description_required if {
	v := object.union(fixture.vocabulary, {"events": [{"name": "order.placed"}]})
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["vocab/event-description-required"]
}

test_event_name_duplicate if {
	v := object.union(fixture.vocabulary, {"events": array.concat(fixture.vocabulary.events, [
		{"name": "order.placed", "description": "the same event twice"},
	])})
	r := obs.validate with input as {"vocabulary": v, "labels": fixture.label_schema, "budget": fixture.budget, "today": today}
	not r.valid
	count([f | some f in r.findings; f.rule == "vocab/event-name-duplicate"]) == 1
}

# --- label schema content --------------------------------------------------------------------

test_metrics_required if {
	s := object.union(fixture.label_schema, {"metrics": []})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": s, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["schema/metrics-required"]
}

test_metric_labels_must_be_declared if {
	# a metric without a labels key has an undeclared label set, not an empty one
	s := object.union(fixture.label_schema, {"metrics": array.concat(fixture.label_schema.metrics, [
		{"name": "carts_total", "description": "carts"},
	])})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": s, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["schema/metric-labels-must-be-array"]
}

test_metric_empty_label_set_is_a_valid_contract if {
	s := object.union(fixture.label_schema, {"metrics": array.concat(fixture.label_schema.metrics, [
		{"name": "carts_total", "description": "carts", "labels": []},
	])})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": s, "budget": fixture.budget, "today": today}
	r.valid == true
}

test_metric_label_duplicate if {
	s := object.union(fixture.label_schema, {"metrics": [{"name": "carts_total", "description": "carts", "labels": ["a", "a"]}]})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": s, "budget": fixture.budget, "today": today}
	not r.valid
	error_rules(r)["schema/metric-label-duplicate"]
}

test_metric_name_duplicate if {
	s := object.union(fixture.label_schema, {"metrics": array.concat(fixture.label_schema.metrics, [
		{"name": "storefront_requests_total", "description": "twice", "labels": []},
	])})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": s, "budget": fixture.budget, "today": today}
	not r.valid
	count([f | some f in r.findings; f.rule == "schema/metric-name-duplicate"]) == 1
}

# --- budget content ------------------------------------------------------------------------------

test_budget_owner_required if {
	b := object.remove(fixture.budget, ["owner"])
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": b, "today": today}
	not r.valid
	error_rules(r)["budget/owner-required"]
}

test_budget_metric_total_required if {
	b := object.union(fixture.budget, {"metrics": [{"name": "carts_total", "allocations": []}]})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": b, "today": today}
	not r.valid
	error_rules(r)["budget/metric-total-required"]
}

test_budget_allocation_maxvalues_required if {
	b := object.union(fixture.budget, {"metrics": [{"name": "carts_total", "total": 10, "allocations": [{"label": "tenant"}]}]})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": b, "today": today}
	not r.valid
	error_rules(r)["budget/allocation-maxvalues-required"]
}

test_budget_allocation_label_duplicate if {
	b := object.union(fixture.budget, {"metrics": [{"name": "carts_total", "total": 10, "allocations": [{"label": "tenant", "maxValues": 2}, {"label": "tenant", "maxValues": 3}]}]})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": b, "today": today}
	not r.valid
	error_rules(r)["budget/allocation-label-duplicate"]
}

# --- budget ↔ schema cross-checks ---------------------------------------------------------------------

test_budget_metric_unknown if {
	b := object.union(fixture.budget, {"metrics": array.concat(fixture.budget.metrics, [
		{"name": "carts_total", "total": 10, "allocations": []},
	])})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": b, "today": today}
	not r.valid
	error_rules(r)["budget/metric-unknown"]
}

test_budget_allocation_label_unknown if {
	b := object.union(fixture.budget, {"metrics": [
		object.union(fixture.budget.metrics[0], {"allocations": array.concat(fixture.budget.metrics[0].allocations, [
			{"label": "session", "maxValues": 4},
		])}),
		fixture.budget.metrics[1],
	]})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": b, "today": today}
	not r.valid
	some f in r.findings
	f.rule == "budget/allocation-label-unknown"
	f.path == "$.budget.metrics[0].allocations[3].label"
}

test_schema_label_unallocated if {
	# the schema declares a label the budget never allocated: its cardinality is unbudgeted
	s := object.union(fixture.label_schema, {"metrics": [
		object.union(fixture.label_schema.metrics[0], {"labels": ["method", "route", "status", "tenant"]}),
		fixture.label_schema.metrics[1],
	]})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": s, "budget": fixture.budget, "today": today}
	not r.valid
	some f in r.findings
	f.rule == "budget/schema-label-unallocated"
	contains(f.message, "label 'tenant'")
}

test_total_below_allocations if {
	# the static cardinality lie: the allocations themselves multiply past the total
	b := object.union(fixture.budget, {"metrics": [
		object.union(fixture.budget.metrics[0], {"allocations": [
			{"label": "method", "maxValues": 100},
			{"label": "route", "maxValues": 100},
			{"label": "status", "maxValues": 100},
		]}),
		fixture.budget.metrics[1],
	]})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema, "budget": b, "today": today}
	not r.valid
	some f in r.findings
	f.rule == "budget/total-below-allocations"
	contains(f.message, "multiply to 1000000")
}

test_cross_checks_silent_when_schema_missing if {
	# the cross-checks must not fire against a missing schema — the
	# schema/missing finding covers that loudly already
	b := object.union(fixture.budget, {"metrics": array.concat(fixture.budget.metrics, [
		{"name": "carts_total", "total": 10, "allocations": []},
	])})
	r := obs.validate with input as {"vocabulary": fixture.vocabulary, "budget": b, "today": today}
	not error_rules(r)["budget/metric-unknown"]
}

# --- lib parity ---------------------------------------------------------------------

test_epoch_is_day_zero if {
	lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	lib.date_to_days("2026-10-20") - lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not lib.is_valid_date("2026-02-30")
}

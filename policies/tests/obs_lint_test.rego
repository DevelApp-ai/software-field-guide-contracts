package obs.lint_test

import rego.v1

import data.obs

import data.obs.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

lint_input(scan) := {
	"vocabulary": fixture.vocabulary,
	"labels": fixture.label_schema,
	"scan": scan,
}

test_good_scan_passes if {
	r := obs.lint with input as lint_input(fixture.good_scan)
	r.valid == true
	count(r.findings) == 0
}

test_event_undeclared if {
	scan := object.union(fixture.good_scan, {"calls": array.concat(fixture.good_scan.calls, [
		fixture.event_call("src/storefront.py", 20, "order.refunded"),
	])})
	r := obs.lint with input as lint_input(scan)
	not r.valid
	some f in r.findings
	f.rule == "lint/event-undeclared"
	contains(f.message, "'order.refunded' emitted at src/storefront.py:20")
	f.path == "$.scan.calls[4]"
}

test_metric_undeclared if {
	scan := object.union(fixture.good_scan, {"calls": array.concat(fixture.good_scan.calls, [
		fixture.metric_call("src/storefront.py", 21, "carts_total", ["tenant"]),
	])})
	r := obs.lint with input as lint_input(scan)
	not r.valid
	some f in r.findings
	f.rule == "lint/metric-undeclared"
	contains(f.message, "'carts_total' emitted at src/storefront.py:21")
}

test_label_undeclared if {
	scan := object.union(fixture.good_scan, {"calls": array.concat(fixture.good_scan.calls, [
		fixture.metric_call("src/storefront.py", 22, "storefront_requests_total", ["method", "route", "status", "order_id"]),
	])})
	r := obs.lint with input as lint_input(scan)
	not r.valid
	some f in r.findings
	f.rule == "lint/label-undeclared"
	contains(f.message, "label 'order_id' on metric 'storefront_requests_total' emitted at src/storefront.py:22")
	contains(f.message, "(method, route, status)")
}

test_each_accreted_label_is_its_own_finding if {
	scan := object.union(fixture.good_scan, {"calls": array.concat(fixture.good_scan.calls, [
		fixture.metric_call("src/storefront.py", 23, "storefront_requests_total", ["order_id", "session_id"]),
	])})
	r := obs.lint with input as lint_input(scan)
	not r.valid
	count([f | some f in r.findings; f.rule == "lint/label-undeclared"]) == 2
}

test_label_checks_skip_undeclared_metrics if {
	# the metric-undeclared finding covers the call; its labels are not
	# double-judged against a metric the schema never declared
	scan := object.union(fixture.good_scan, {"calls": array.concat(fixture.good_scan.calls, [
		fixture.metric_call("src/storefront.py", 24, "carts_total", ["order_id"]),
	])})
	r := obs.lint with input as lint_input(scan)
	not r.valid
	count([f | some f in r.findings; f.rule == "lint/label-undeclared"]) == 0
	error_rules(r)["lint/metric-undeclared"]
}

test_scan_missing if {
	r := obs.lint with input as {"vocabulary": fixture.vocabulary, "labels": fixture.label_schema}
	not r.valid
	error_rules(r)["scan/missing"]
}

test_scan_calls_must_be_array if {
	r := obs.lint with input as lint_input({"calls": "yes"})
	not r.valid
	error_rules(r)["scan/calls-must-be-array"]
}

test_scan_call_kind_invalid if {
	broken := object.union(fixture.metric_call("src/storefront.py", 25, "storefront_requests_total", []), {"kind": "log"})
	r := obs.lint with input as lint_input({"calls": [broken]})
	not r.valid
	error_rules(r)["scan/call-kind-invalid"]
}

test_scan_call_line_required if {
	broken := fixture.event_call("src/storefront.py", 0, "order.placed")
	r := obs.lint with input as lint_input({"calls": [broken]})
	not r.valid
	error_rules(r)["scan/call-line-required"]
}

test_scan_call_labels_must_be_array if {
	broken := object.union(fixture.event_call("src/storefront.py", 5, "order.placed"), {"labels": "method"})
	r := obs.lint with input as lint_input({"calls": [broken]})
	not r.valid
	error_rules(r)["scan/call-labels-must-be-array"]
}

test_malformed_calls_are_not_lint_judged if {
	# shape findings cover the malformed call; declaration checks skip it
	r := obs.lint with input as lint_input({"calls": [{"file": "x.py", "line": 1, "kind": "event"}]})
	not r.valid
	error_rules(r)["scan/call-name-required"]
	not error_rules(r)["lint/event-undeclared"]
}

test_lint_requires_both_vocabularies if {
	r := obs.lint with input as {"scan": fixture.good_scan}
	not r.valid
	error_rules(r)["vocab/missing"]
	error_rules(r)["schema/missing"]
}

test_input_must_be_object if {
	r := obs.lint with input as "lint me"
	not r.valid
	r.findings[0].rule == "input/invalid"
}

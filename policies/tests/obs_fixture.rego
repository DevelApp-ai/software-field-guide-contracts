# Shared fixture for the obs tests: one small, valid set of contracts in
# the storefront flavor of the book's examples — an event-name
# vocabulary, a metric label schema, a cardinality budget with an owner,
# plus scan and observation builders.
#
# The review dates are chosen relative to the CI anchor date 2026-10-20.
package obs.fixture

import rego.v1

today := "2026-10-20"

vocabulary := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"events": [
		{"name": "order.placed", "description": "An order was accepted and awaits settlement"},
		{"name": "order.cancelled", "description": "A customer cancelled an open order"},
		{"name": "payment.settled", "description": "A charge was captured by the payment provider"},
	],
}

label_schema := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"metrics": [
		{
			"name": "storefront_requests_total",
			"description": "Storefront HTTP requests",
			"labels": ["method", "route", "status"],
		},
		{
			"name": "payment_settlements_total",
			"description": "Settlement outcomes",
			"labels": ["result", "provider"],
		},
	],
}

budget := {
	"owner": "Storefront team",
	"reviewedOn": "2026-10-01",
	"metrics": [
		{
			"name": "storefront_requests_total",
			"total": 4000,
			"allocations": [
				{"label": "method", "maxValues": 2},
				{"label": "route", "maxValues": 2},
				{"label": "status", "maxValues": 100},
			],
		},
		{
			"name": "payment_settlements_total",
			"total": 200,
			"allocations": [
				{"label": "result", "maxValues": 2},
				{"label": "provider", "maxValues": 10},
			],
		},
	],
}

# The budget as the label-accretion PR left it: order_id declared in the
# schema, allocated a token 50 values, total untouched.
breach_schema := {
	"version": 2,
	"reviewedOn": "2026-10-18",
	"metrics": [
		{
			"name": "storefront_requests_total",
			"description": "Storefront HTTP requests",
			"labels": ["method", "route", "status", "order_id"],
		},
		label_schema.metrics[1],
	],
}

breach_budget := {
	"owner": "Storefront team",
	"reviewedOn": "2026-10-18",
	"metrics": [
		{
			"name": "storefront_requests_total",
			"total": 4000,
			"allocations": [
				{"label": "method", "maxValues": 2},
				{"label": "route", "maxValues": 2},
				{"label": "status", "maxValues": 100},
				{"label": "order_id", "maxValues": 50},
			],
		},
		budget.metrics[1],
	],
}

# --- scan builders ------------------------------------------------------------

event_call(file, line, name) := {
	"file": file,
	"line": line,
	"kind": "event",
	"name": name,
	"labels": [],
}

metric_call(file, line, name, labels) := {
	"file": file,
	"line": line,
	"kind": "metric",
	"name": name,
	"labels": labels,
}

good_scan := {
	"calls": [
		event_call("src/storefront.py", 5, "order.placed"),
		event_call("src/storefront.py", 9, "order.cancelled"),
		metric_call("src/storefront.py", 6, "storefront_requests_total", ["method", "route", "status"]),
		metric_call("src/payments.py", 3, "payment_settlements_total", ["result", "provider"]),
	],
}

# --- observation row builders ----------------------------------------------------

obs_row(metric, label, distinct) := {
	"metric": metric,
	"label": label,
	"distinct": distinct,
}

good_observations := [
	obs_row("storefront_requests_total", "method", 2),
	obs_row("storefront_requests_total", "route", 2),
	obs_row("storefront_requests_total", "status", 37),
	obs_row("payment_settlements_total", "result", 2),
	obs_row("payment_settlements_total", "provider", 3),
]

# The metrics export after the order_id label reached production.
breach_observations := array.concat(good_observations, [
	obs_row("storefront_requests_total", "order_id", 1204),
])

# Shared fixture for the segment tests: one small, valid estate after
# the microsegmentation chapter's five-segment model — web, api, db,
# worker, external — four rules (three enforced, one in audit mode
# awaiting its promotion), two fabrics rendered per rule, a seeded
# flow window with traffic for every rule, and a promotion PR citing
# that evidence. The review dates are chosen relative to the CI
# anchor date 2026-10-20.
package segment.fixture

import rego.v1

today := "2026-10-20"

contract_file := "segment-contract.yaml"

renders_file := "segment-renders.yaml"

flows_file := "flows.yaml"

contract := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"owner": "Platform team",
	"segments": ["web", "api", "db", "worker", "external"],
	"rules": [
		{"id": "R1", "from": "web", "to": "api", "type": "tcp", "port": 443, "direction": "egress", "mode": "enforce"},
		{"id": "R2", "from": "api", "to": "db", "type": "tcp", "port": 5432, "direction": "egress", "mode": "enforce"},
		{"id": "R3", "from": "worker", "to": "api", "type": "tcp", "port": 443, "direction": "egress", "mode": "audit"},
		{
			"id": "R4",
			"from": "external",
			"to": "web",
			"type": "tcp",
			"port": 443,
			"direction": "ingress",
			"mode": "enforce",
			"exceptions": [{
				"reason": "pen-test window — the load generator's traffic is expected until the contract is re-rendered",
				"expiresOn": "2026-12-01",
			}],
		},
	],
}

# The rendered policies: both fabrics render every rule, in the same
# direction, type, and port the contract declares.
renders := {
	"version": 1,
	"reviewedOn": "2026-10-18",
	"fabrics": ["cloud", "host-firewall"],
	"rules": [
		{"fabric": "cloud", "rule": "R1", "direction": "egress", "type": "tcp", "port": 443},
		{"fabric": "host-firewall", "rule": "R1", "direction": "egress", "type": "tcp", "port": 443},
		{"fabric": "cloud", "rule": "R2", "direction": "egress", "type": "tcp", "port": 5432},
		{"fabric": "host-firewall", "rule": "R2", "direction": "egress", "type": "tcp", "port": 5432},
		{"fabric": "cloud", "rule": "R3", "direction": "egress", "type": "tcp", "port": 443},
		{"fabric": "host-firewall", "rule": "R3", "direction": "egress", "type": "tcp", "port": 443},
		{"fabric": "cloud", "rule": "R4", "direction": "ingress", "type": "tcp", "port": 443},
		{"fabric": "host-firewall", "rule": "R4", "direction": "ingress", "type": "tcp", "port": 443},
	],
}

# The flow evidence: one seeded window with traffic for every rule —
# the evidence the promotion PR cites and the dead-rule review reads.
flows := {
	"reviewedOn": "2026-10-16",
	"window": {"from": "2026-10-01", "to": "2026-10-15"},
	"flows": [
		{"from": "web", "to": "api", "type": "tcp", "port": 443, "count": 812},
		{"from": "api", "to": "db", "type": "tcp", "port": 5432, "count": 147},
		{"from": "worker", "to": "api", "type": "tcp", "port": 443, "count": 14},
		{"from": "external", "to": "web", "type": "tcp", "port": 443, "count": 2105},
	],
}

# The promotion PR: moves the audit rule to enforce, citing the flow
# evidence and claiming exactly the window it covers.
promotion := {
	"pr": "PR-512",
	"rule": "R3",
	"to": "enforce",
	"evidenceFile": flows_file,
	"window": {"from": "2026-10-01", "to": "2026-10-15"},
}

validate_input(contract_doc) := {
	"contract": contract_doc,
	"today": today,
}

gate_input(contract_doc, renders_doc, flows_doc, promotion_doc) := {
	"contract": contract_doc,
	"renders": renders_doc,
	"flows": flows_doc,
	"promotion": promotion_doc,
	"today": today,
	"contractFile": contract_file,
	"rendersFile": renders_file,
	"flowsFile": flows_file,
}

control_input := gate_input(contract, renders, flows, promotion)

# --- override helpers --------------------------------------------------------
#
# The #69 lesson, applied: an array comprehension with a condition in
# the body filters, so per-element overrides go through explicit
# two-definition helpers that always answer — the row itself when it
# does not match, the patched row when it does.

# Field replacement, not merge: object.union deep-merges object values,
# so a patch that means "this object is now X" removes the key first.
replace_field(obj, patch) := object.union(object.remove(obj, object.keys(patch)), patch)

# Override one top-level field of a document.
with_field(doc, patch) := replace_field(doc, patch)

# Override one field of one contract rule, by id.
with_rule_field(contract_doc, id, patch) := object.union(contract_doc, {"rules": [rule_field_override(r, id, patch) |
	some r in contract_doc.rules
]})

rule_field_override(r, id, patch) := replace_field(r, patch) if object.get(r, "id", null) == id

rule_field_override(r, id, patch) := r if object.get(r, "id", null) != id

# Override one field of the first exception on one contract rule.
with_exception_field(contract_doc, id, patch) := object.union(contract_doc, {"rules": [exception_field_override(r, id, patch) |
	some r in contract_doc.rules
]})

exception_field_override(r, id, patch) := replace_field(r, {"exceptions": [exception_override(e, patch) |
	some e in object.get(r, "exceptions", [])
]}) if {
	object.get(r, "id", null) == id
}

exception_field_override(r, id, patch) := r if object.get(r, "id", null) != id

exception_override(e, patch) := replace_field(e, patch)

# Override one field of one render row, by rule id and fabric.
with_render_field(renders_doc, rule, fabric, patch) := object.union(renders_doc, {"rules": [render_field_override(x, rule, fabric, patch) |
	some x in renders_doc.rules
]})

render_field_override(x, rule, fabric, patch) := replace_field(x, patch) if {
	object.get(x, "rule", null) == rule
	object.get(x, "fabric", null) == fabric
}

render_field_override(x, rule, fabric, patch) := x if {
	object.get(x, "rule", null) != rule
}

render_field_override(x, rule, fabric, patch) := x if {
	object.get(x, "rule", null) == rule
	object.get(x, "fabric", null) != fabric
}

# Remove the render rows for one rule on one fabric — the seeded
# missing-in-render drift.
without_render(renders_doc, rule, fabric) := object.union(renders_doc, {"rules": [x |
	some x in renders_doc.rules
	not render_is(x, rule, fabric)
]})

render_is(x, rule, fabric) if {
	object.get(x, "rule", null) == rule
	object.get(x, "fabric", null) == fabric
}

# Add one render row — the seeded phantom rule.
with_render(renders_doc, row) := object.union(renders_doc, {"rules": array.concat(renders_doc.rules, [row])})

# Remove every observed flow between two segments — the seeded dead
# rule: the rule stays rendered, the traffic vanishes.
without_flows(flows_doc, from_segment, to_segment) := object.union(flows_doc, {"flows": [f |
	some f in flows_doc.flows
	not flow_is(f, from_segment, to_segment)
]})

flow_is(f, from_segment, to_segment) if {
	object.get(f, "from", null) == from_segment
	object.get(f, "to", null) == to_segment
}

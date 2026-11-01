package segment.gate_test

import rego.v1

import data.segment

import data.segment.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

error_count(r) := count([f | some f in r.findings; f.severity == "error"])

# --- the control: one contract, two fabrics, everything agrees ------------------

test_control_gate_passes_and_renders_consistent if {
	r := segment.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
	count(r.rules) == 4

	# one card per contract rule, sorted by rule id
	r.rules[0].rule == "R1"
	r.rules[0].verdict == "consistent"
	r.rules[1].rule == "R2"
	r.rules[1].verdict == "consistent"
	r.rules[2].rule == "R3"
	r.rules[2].verdict == "audit"
	r.rules[3].rule == "R4"
	r.rules[3].verdict == "consistent"
}

test_control_card_details if {
	r := segment.gate with input as fixture.control_input
	r.rules[0].detail == "rendered on cloud, host-firewall; 812 matched flows across the window"
	r.rules[2].detail == "promotion PR-512 to enforce cites flows.yaml — 14 matched flows in the window"
}

test_control_promotion_evidence_in_hand_passes if {
	r := segment.gate with input as fixture.control_input
	not error_rules(r)["promotion/no-flow-evidence"]
	not error_rules(r)["promotion/no-matched-flows"]
	not error_rules(r)["promotion/window-outside-evidence"]
}

# --- input shape ------------------------------------------------------------

test_input_must_be_object if {
	r := segment.gate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_contract_missing if {
	r := segment.gate with input as object.remove(fixture.control_input, {"contract"})
	not r.valid
	error_rules(r)["contract/missing"]
}

test_renders_missing if {
	r := segment.gate with input as object.remove(fixture.control_input, {"renders"})
	not r.valid
	error_rules(r)["renders/missing"]
}

# --- the render joins: the issue's core failure modes -------------------------

# The done-when: a render-mismatch variant bites citing BOTH files.
test_missing_render_bites_once_citing_both_files if {
	renders := fixture.without_render(fixture.renders, "R2", "cloud")
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	r.verdict == "inconsistent"
	error_count(r) == 1
	error_rules(r)["render/rule-missing"]

	# the message cites the contract file and the renders file
	some f in r.findings
	f.rule == "render/rule-missing"
	contains(f.message, fixture.contract_file)
	contains(f.message, "segment-renders.yaml")
	contains(f.message, "'cloud'")
	contains(f.message, "'R2'")

	# the path cites the contract rule row
	startswith(f.path, "$.contract.rules[")
}

test_not_in_contract_bites_citing_both_files if {
	renders := fixture.with_render(fixture.renders, {"fabric": "cloud", "rule": "R9", "direction": "egress", "type": "tcp", "port": 8080})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_count(r) == 1
	error_rules(r)["render/rule-unknown"]

	some f in r.findings
	f.rule == "render/rule-unknown"
	contains(f.message, fixture.renders_file)
	contains(f.message, fixture.contract_file)
}

test_direction_mismatch if {
	renders := fixture.with_render_field(fixture.renders, "R4", "host-firewall", {"direction": "egress"})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_count(r) == 1
	error_rules(r)["render/direction-mismatch"]
}

test_type_mismatch if {
	renders := fixture.with_render_field(fixture.renders, "R2", "cloud", {"type": "udp"})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_count(r) == 1
	error_rules(r)["render/type-mismatch"]
}

test_port_mismatch if {
	renders := fixture.with_render_field(fixture.renders, "R1", "cloud", {"port": 8443})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_count(r) == 1
	error_rules(r)["render/port-mismatch"]
}

test_render_duplicate if {
	renders := fixture.with_render(fixture.renders, {"fabric": "cloud", "rule": "R1", "direction": "egress", "type": "tcp", "port": 443})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_rules(r)["render/rule-duplicate"]
}

test_fabric_undeclared if {
	renders := fixture.with_render(fixture.renders, {"fabric": "cni", "rule": "R1", "direction": "egress", "type": "tcp", "port": 443})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_rules(r)["render/fabric-undeclared"]
}

test_fabrics_required if {
	renders := fixture.with_field(fixture.renders, {"fabrics": []})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_rules(r)["fabrics/required"]
}

test_fabric_duplicate if {
	renders := fixture.with_field(fixture.renders, {"fabrics": ["cloud", "cloud", "host-firewall"]})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_rules(r)["fabric/name-duplicate"]
}

test_renders_version_required if {
	renders := fixture.with_field(fixture.renders, {"version": null})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_rules(r)["renders/version-required"]
}

test_renders_stale if {
	renders := fixture.with_field(fixture.renders, {"reviewedOn": "2024-10-01"})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_rules(r)["renders/reviewed-stale"]
}

test_render_row_invalid if {
	renders := fixture.with_render(fixture.renders, {"fabric": "cloud", "rule": "R1", "direction": "north"})
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_rules(r)["render/row-invalid"]
}

# --- the flow evidence ---------------------------------------------------------

test_flows_window_required if {
	flows := fixture.with_field(fixture.flows, {"window": null})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, flows, fixture.promotion)
	not r.valid
	error_rules(r)["flows/window-required"]
}

test_flows_window_in_future if {
	flows := fixture.with_field(fixture.flows, {"window": {"from": "2026-10-01", "to": "2026-11-01"}})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, flows, fixture.promotion)
	not r.valid
	error_rules(r)["flows/window-in-future"]
}

test_flow_row_invalid if {
	flows := fixture.with_field(fixture.flows, {"flows": [{"from": "web", "to": "api", "type": "tcp", "port": 443, "count": 0}]})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, flows, fixture.promotion)
	not r.valid
	error_rules(r)["flow/row-invalid"]
}

# The done-when: a dead-rule variant flags the rule — the review
# flag, not an error: the estate is consistent, the rule is dead.
test_dead_rule_review_flag_names_the_rule if {
	flows := fixture.without_flows(fixture.flows, "api", "db")
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, flows, fixture.promotion)
	r.valid == true
	r.verdict == "review"
	error_count(r) == 0
	warning_rules(r)["flows/dead-rule"]

	some f in r.findings
	f.rule == "flows/dead-rule"
	contains(f.message, "'R2'")
	contains(f.message, fixture.flows_file)

	# the card renders the rule dead, with its zero
	dead := [c | some c in r.rules; c.rule == "R2"][0]
	dead.verdict == "dead"
}

# --- the promotion: evidence, not assertion --------------------------------------

# The done-when: promotion-without-flow-evidence fails.
test_promotion_without_evidence_fails if {
	promotion := fixture.with_field(fixture.promotion, {"evidenceFile": null})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, fixture.flows, promotion)
	not r.valid
	error_count(r) == 1
	error_rules(r)["promotion/no-flow-evidence"]
}

test_promotion_citing_evidence_not_in_hand_fails if {
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, null, fixture.promotion)
	not r.valid
	error_rules(r)["promotion/no-flow-evidence"]
}

test_promotion_without_matched_flows_fails if {
	flows := fixture.without_flows(fixture.flows, "worker", "api")
	promotion := fixture.promotion
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, flows, promotion)
	not r.valid
	error_rules(r)["promotion/no-matched-flows"]
}

test_promotion_window_outside_evidence if {
	promotion := fixture.with_field(fixture.promotion, {"window": {"from": "2026-10-16", "to": "2026-10-31"}})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, fixture.flows, promotion)
	not r.valid
	error_count(r) == 1
	error_rules(r)["promotion/window-outside-evidence"]
}

test_promotion_rule_unknown if {
	promotion := fixture.with_field(fixture.promotion, {"rule": "R9"})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, fixture.flows, promotion)
	not r.valid
	error_rules(r)["promotion/rule-unknown"]
}

test_promotion_of_enforced_rule_not_audit if {
	promotion := fixture.with_field(fixture.promotion, {"rule": "R2"})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, fixture.flows, promotion)
	not r.valid
	error_rules(r)["promotion/rule-not-audit"]
}

test_promotion_target_invalid if {
	promotion := fixture.with_field(fixture.promotion, {"to": "deny"})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, fixture.flows, promotion)
	not r.valid
	error_rules(r)["promotion/target-invalid"]
}

test_promotion_pr_required if {
	promotion := fixture.with_field(fixture.promotion, {"pr": ""})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, fixture.flows, promotion)
	not r.valid
	error_rules(r)["promotion/pr-required"]
}

test_promotion_window_invalid if {
	promotion := fixture.with_field(fixture.promotion, {"window": {"from": "2026-10-15", "to": "2026-10-01"}})
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, fixture.flows, promotion)
	not r.valid
	error_rules(r)["promotion/window-invalid"]
}

test_no_promotion_document_is_clean if {
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, fixture.flows, null)
	r.valid == true
	r.verdict == "consistent"

	# the audit rule awaits its promotion PR, honestly
	awaiting := [c | some c in r.rules; c.rule == "R3"][0]
	awaiting.verdict == "audit"
	awaiting.detail == "awaiting a promotion PR with flow evidence"
}

test_promotion_cites_evidence_not_in_hand_card if {
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, null, fixture.promotion)
	pending := [c | some c in r.rules; c.rule == "R3"][0]
	pending.detail == "promotion cites evidence not yet in hand"
}

# --- the verdict ladder ----------------------------------------------------------

test_verdict_inconsistent_on_errors if {
	renders := fixture.without_render(fixture.renders, "R2", "cloud")
	r := segment.gate with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	r.verdict == "inconsistent"
}

test_verdict_review_on_warnings_only if {
	flows := fixture.without_flows(fixture.flows, "api", "db")
	r := segment.gate with input as fixture.gate_input(fixture.contract, fixture.renders, flows, fixture.promotion)
	r.verdict == "review"
}

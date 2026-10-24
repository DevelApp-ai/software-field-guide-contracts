package alerts.audit_test

import rego.v1

import data.alerts

import data.alerts.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_good_contract_and_register_pass_the_audit if {
	r := alerts.audit with input as fixture.gate_input(fixture.contract, fixture.register)
	r.valid == true
	count(r.findings) == 0
	count(r.linkages) == 2
}

test_audit_composes_both_analyzers if {
	# one contract-side failure (a runbook without its escalation clock)
	# and one register-side failure (an unlinked alert) answer in one
	# evaluation — the playground renders both from a single verdict
	c := object.union(fixture.contract, {"runbooks": [
		fixture.contract.runbooks[0],
		object.remove(fixture.contract.runbooks[1], ["escalationClock"]),
	]})
	reg := object.union(fixture.register, {"firedAlerts": array.concat(fixture.register.firedAlerts, [
		{"alert": "storefront-latency", "firedOn": "2026-10-15"},
	])})
	r := alerts.audit with input as fixture.gate_input(c, reg)
	not r.valid
	error_rules(r)["runbook/escalation-clock-required"]
	error_rules(r)["alerts/no-record-linkage"]

	# the linkage card still renders, absence included
	some l in r.linkages
	l.alert == "storefront-latency"
	l.record == null
}

test_audit_reports_a_missing_contract_once if {
	# validate and gate both need the contract; the findings are sets,
	# so the shared condition is reported once, not twice
	r := alerts.audit with input as {"register": fixture.register, "today": fixture.today}
	not r.valid
	count([f | some f in r.findings; f.rule == "alerting/missing"]) == 1
}

test_audit_is_deterministic if {
	a := alerts.audit with input as fixture.gate_input(fixture.contract, fixture.register)
	b := alerts.audit with input as fixture.gate_input(fixture.contract, fixture.register)
	a == b
}

test_wasm_shape_is_stable if {
	# the playground and e2e rely on the three keys; the shape is part
	# of the contract
	r := alerts.audit with input as fixture.gate_input(fixture.contract, fixture.register)
	object.keys(r) == {"findings", "linkages", "valid"}
}

package erasure.audit_test

import rego.v1

import data.erasure

import data.erasure.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_good_registry_and_case_pass_the_audit if {
	r := erasure.audit with input as fixture.gate_input(fixture.keys, fixture.case_forgotten)
	r.valid == true
	count(r.findings) == 0
	count(r.stores) == 4
	r.verdict == "forgotten"
}

test_audit_composes_both_analyzers if {
	# one registry-side failure (a destroyed key without its evidence
	# record) and one case-side failure (a replica without its sweep
	# record) answer in one evaluation — the playground renders both
	# from a single verdict
	k := fixture.without_key_field(fixture.keys, "tenant-acme-dek-004", "destroyedBy")
	c := fixture.without_sweep(fixture.case_forgotten, "postgres-replica-eu")
	r := erasure.audit with input as fixture.gate_input(k, c)
	not r.valid
	r.verdict == "incomplete"
	error_rules(r)["key/destroyed-by-required"]
	error_rules(r)["sweep/store-unswept"]

	# the store cards still render, the unswept replica included
	replica := [s | some s in r.stores; s.store == "postgres-replica-eu"][0]
	replica.verdict == "unswept"
}

test_audit_reports_a_missing_registry_once if {
	# validate and gate both need the registry; the findings are sets,
	# so the shared condition is reported once, not twice
	r := erasure.audit with input as {"case": fixture.case_forgotten, "today": fixture.today}
	not r.valid
	count([f | some f in r.findings; f.rule == "keys/missing"]) == 1
}

test_audit_is_deterministic if {
	a := erasure.audit with input as fixture.gate_input(fixture.keys, fixture.case_forgotten)
	b := erasure.audit with input as fixture.gate_input(fixture.keys, fixture.case_forgotten)
	a == b
}

test_wasm_shape_is_stable if {
	# the playground and e2e rely on the four keys; the shape is part
	# of the contract
	r := erasure.audit with input as fixture.gate_input(fixture.keys, fixture.case_forgotten)
	object.keys(r) == {"findings", "stores", "valid", "verdict"}
}

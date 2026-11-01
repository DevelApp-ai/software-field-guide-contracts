package segment.audit_test

import rego.v1

import data.segment

import data.segment.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

# The composed entry point: the contract validated and the renders,
# flow evidence, and promotion gated against it — one verdict, one
# findings list, the per-rule cards alongside.
test_control_audit_passes_and_renders_consistent if {
	r := segment.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
	count(r.rules) == 4
}

test_audit_answers_in_the_stable_shape if {
	r := segment.audit with input as fixture.control_input
	object.keys(r) == {"findings", "rules", "valid", "verdict"}
}

# The contract-time findings ride along: a TTL-expired exception
# makes the composed verdict inconsistent.
test_audit_catches_expired_exception if {
	contract := fixture.with_exception_field(fixture.contract, "R4", {"expiresOn": "2026-09-01"})
	r := segment.audit with input as fixture.gate_input(contract, fixture.renders, fixture.flows, fixture.promotion)
	not r.valid
	r.verdict == "inconsistent"
	error_rules(r)["exception/ttl-expired"]
}

test_audit_catches_the_missing_render if {
	renders := fixture.without_render(fixture.renders, "R2", "cloud")
	r := segment.audit with input as fixture.gate_input(fixture.contract, renders, fixture.flows, fixture.promotion)
	not r.valid
	error_rules(r)["render/rule-missing"]
}

test_audit_renders_the_review_verdict if {
	flows := fixture.without_flows(fixture.flows, "api", "db")
	r := segment.audit with input as fixture.gate_input(fixture.contract, fixture.renders, flows, fixture.promotion)
	r.valid == true
	r.verdict == "review"
	warning_rules(r)["flows/dead-rule"]
}

# The findings of the two analyzers are sets, so a shared condition
# (a missing contract) is reported once, not twice.
test_audit_dedupes_the_shared_condition if {
	r := segment.audit with input as object.remove(fixture.control_input, {"contract"})
	not r.valid
	count([f | some f in r.findings; f.rule == "contract/missing"]) == 1
}

package ingress.audit_test

import rego.v1

import data.ingress

import data.ingress.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

# The composed entry point: the posture case validated (wildcards
# contained, default-deny, certificate rotation clocks, SLOs with
# pagers, every route class logged) and the kill path gated against
# the drill record — one verdict, one findings list, the posture
# cards alongside.
test_control_audit_passes_and_renders_hardened if {
	r := ingress.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "hardened"
	count(r.cards) == 10
}

test_audit_answers_in_the_stable_shape if {
	r := ingress.audit with input as fixture.control_input
	object.keys(r) == {"cards", "findings", "valid", "verdict"}
}

# The case-time findings ride along: an expired certificate makes
# the composed verdict exposed.
test_audit_catches_the_expired_cert if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"notAfter": "2026-09-30"})
	r := ingress.audit with input as fixture.gate_input(c, fixture.drill)
	not r.valid
	r.verdict == "exposed"
	error_rules(r)["cert/expired"]
}

test_audit_catches_the_broad_wildcard if {
	c := fixture.with_domain_field(fixture.case, "*.dev.internal", {"pattern": "*.example.com"})
	r := ingress.audit with input as fixture.gate_input(c, fixture.drill)
	not r.valid
	r.verdict == "exposed"
	error_rules(r)["domain/too-broad"]
}

test_audit_renders_the_review_verdict_for_a_late_rotation if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"notAfter": "2026-11-10"})
	r := ingress.audit with input as fixture.gate_input(c, fixture.drill)
	r.valid == true
	r.verdict == "review"
	warning_rules(r)["cert/near-expiry"]
}

# The findings of the two analyzers are sets, so a shared condition
# (a missing case) is reported once, not twice.
test_audit_dedupes_the_shared_condition if {
	r := ingress.audit with input as object.remove(fixture.control_input, {"case"})
	not r.valid
	count([f | some f in r.findings; f.rule == "case/missing"]) == 1
}

test_audit_catches_the_missing_default_deny if {
	c := fixture.with_field(fixture.case, {"requestPolicy": {"defaultDeny": false, "decision": "admit everything"}})
	r := ingress.audit with input as fixture.gate_input(c, fixture.drill)
	not r.valid
	r.verdict == "exposed"
	error_rules(r)["requestpolicy/default-deny-required"]
}

test_audit_catches_the_never_rehearsed_kill_path if {
	d := fixture.with_field(fixture.drill, {"drills": []})
	r := ingress.audit with input as fixture.gate_input(fixture.case, d)
	not r.valid
	r.verdict == "exposed"
	error_rules(r)["killpath/never-rehearsed"]
}

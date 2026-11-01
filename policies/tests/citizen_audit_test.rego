package citizen.audit_test

import rego.v1

import data.citizen

import data.citizen.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

advisory_rules(r) := {f.rule | some f in r.findings; f.severity == "advisory"}

# The composed entry point: the app manifest validated (components
# with behaviors, bindings with names, modes, and rails, actions
# used, guardrails with versions) and the app judged against its
# spec and the platform's registry — one verdict, one findings
# list, the advice cards alongside.
test_control_audit_passes_and_renders_aligned if {
	r := citizen.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "aligned"
	count(r.cards) == 8
}

test_audit_answers_in_the_stable_shape if {
	r := citizen.audit with input as fixture.control_input
	object.keys(r) == {"cards", "findings", "valid", "verdict"}
}

# The manifest-time findings ride along: a manifest without its
# version makes the composed verdict unreadable.
test_audit_catches_the_manifest_without_a_version if {
	m := fixture.with_field(fixture.manifest, {"version": null})
	r := citizen.audit with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	not r.valid
	r.verdict == "unreadable"
	error_rules(r)["manifest/version-required"]
}

# The findings of the two analyzers are sets, so a shared condition
# (a missing manifest) is reported once, not twice.
test_audit_dedupes_the_shared_condition if {
	r := citizen.audit with input as object.remove(fixture.control_input, {"manifest"})
	not r.valid
	count([f | some f in r.findings; f.rule == "manifest/missing"]) == 1
}

# The four drifts are advisories in the composed answer too: the
# gate stays green, the advice is on the record.
test_audit_advises_on_the_escape_hatch if {
	m := fixture.with_binding_field(fixture.manifest, "audit-log", {"via": "raw-sql"})
	r := citizen.audit with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.valid == true
	r.verdict == "advises changes"
	advisory_rules(r)["binding/escape-hatch"]
}

test_audit_advises_on_the_guardrail_below_the_floor if {
	m := fixture.with_guardrail_field(fixture.manifest, "data-guardrail", {"version": 2})
	r := citizen.audit with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.valid == true
	r.verdict == "advises changes"
	advisory_rules(r)["guardrail/below-floor"]
}

test_audit_advises_on_the_unspecced_action if {
	m := fixture.with_field(fixture.manifest, {"actions": array.concat(fixture.manifest.actions, ["expense.purge"])})
	r := citizen.audit with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.valid == true
	r.verdict == "advises changes"
	advisory_rules(r)["action/outside-rails"]
}

test_audit_advises_on_the_uncovered_behavior if {
	m := fixture.with_component_field(fixture.manifest, "claim-rules", {"behavior": "deletes old claims"})
	r := citizen.audit with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	r.valid == true
	r.verdict == "advises changes"
	advisory_rules(r)["behavior/uncovered-by-spec"]
}

# An advisory never drags the verdict below the manifest's own
# validity: an unreadable manifest and an escape hatch together
# report both, honestly.
test_audit_reports_the_error_and_the_advisory_together if {
	m := fixture.with_binding_field(fixture.with_field(fixture.manifest, {"version": null}), "audit-log", {"via": "raw-sql"})
	r := citizen.audit with input as fixture.gate_input(m, fixture.spec, fixture.registry)
	not r.valid
	r.verdict == "unreadable"
	error_rules(r)["manifest/version-required"]
	advisory_rules(r)["binding/escape-hatch"]
}

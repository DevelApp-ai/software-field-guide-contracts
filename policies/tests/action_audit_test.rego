package actions.audit_test

import rego.v1

import data.actions

import data.actions.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_good_registry_and_manifest_pass_the_audit if {
	r := actions.audit with input as fixture.gate_input(fixture.registry, fixture.manifest)
	r.valid == true
	count(r.findings) == 0
	count(r.scoping) == 3
}

test_audit_composes_both_analyzers if {
	# one registry-side failure (a Critical action on auto-confirm) and
	# one manifest-side failure (a phantom grant) answer in one
	# evaluation — the playground renders both from a single verdict
	reg := fixture.with_action_field(fixture.registry, "send-invoice-email", {"confirmation": "auto-confirm"})
	man := fixture.with_grant(fixture.manifest, "chargeback-agent", {
		"action": "purge-invoice-archive",
		"argumentScopes": [],
	})
	r := actions.audit with input as fixture.gate_input(reg, man)
	not r.valid
	error_rules(r)["action/confirm-required-at-level"]
	error_rules(r)["manifest/action-unknown"]

	# the scoping card still renders, grants included
	some row in r.scoping
	row.agent == "chargeback-agent"
	"purge-invoice-archive" in row.actions
}

test_audit_reports_a_missing_registry_once if {
	# validate and gate both need the registry; the findings are sets,
	# so the shared condition is reported once, not twice
	r := actions.audit with input as {"manifest": fixture.manifest, "today": fixture.today}
	not r.valid
	count([f | some f in r.findings; f.rule == "registry/missing"]) == 1
}

test_audit_is_deterministic if {
	a := actions.audit with input as fixture.gate_input(fixture.registry, fixture.manifest)
	b := actions.audit with input as fixture.gate_input(fixture.registry, fixture.manifest)
	a == b
}

test_wasm_shape_is_stable if {
	# the playground and e2e rely on the three keys; the shape is part
	# of the contract
	r := actions.audit with input as fixture.gate_input(fixture.registry, fixture.manifest)
	object.keys(r) == {"findings", "scoping", "valid"}
}

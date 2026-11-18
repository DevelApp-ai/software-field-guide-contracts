package component.audit_test

import rego.v1

import data.component

import data.component.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# The composed entry point: the package manifest validated (its
# identity and tier, the artifact digest, the recorded signature,
# attestation, and provenance, the pinned dependencies) and judged
# against the component registry — one verdict, one findings list,
# the conformance cards alongside.
test_control_audit_passes_and_renders_consistent if {
	r := component.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
	count(r.cards) == 2
}

test_audit_answers_in_the_stable_shape if {
	r := component.audit with input as fixture.control_input
	object.keys(r) == {"cards", "findings", "valid", "verdict"}
}

# The manifest-time findings ride along: a package without its
# version makes the composed verdict unreadable.
test_audit_catches_the_package_without_a_version if {
	p := fixture.with_field(fixture.package_manifest, {"version": null})
	r := component.audit with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	r.verdict == "unreadable"
	error_rules(r)["package/version-required"]
}

# The findings of the two analyzers are sets, so a shared condition
# (a missing package manifest) is reported once, not twice.
test_audit_dedupes_the_shared_condition if {
	r := component.audit with input as object.remove(fixture.control_input, {"package"})
	not r.valid
	count([f | some f in r.findings; f.rule == "package/missing"]) == 1
}

# The five drifts are conformance failures in the composed answer
# too: the gate refuses, and the verdict says drifts.
test_audit_refuses_the_unregistered_package if {
	p := fixture.with_field(fixture.package_manifest, {"version": "1.5.0"})
	r := component.audit with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	r.verdict == "drifts"
	error_rules(r)["gate/package-unregistered"]
}

test_audit_refuses_the_digest_drift if {
	p := fixture.with_field(fixture.package_manifest, {"artifactDigest": "4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80", "signature": {"keyId": "key-2026-q4", "signedDigest": "4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80"}})
	r := component.audit with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	r.verdict == "drifts"
	error_rules(r)["gate/package-digest-drift"]
}

test_audit_refuses_the_stale_pin if {
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"digest": "aaf1965eeee9f4c7eaf29bbb5b32eb477629a35c41d21dd75037af59b0ee8e1c"})
	r := component.audit with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	r.verdict == "drifts"
	error_rules(r)["gate/dependency-digest-mismatch"]
}

test_audit_refuses_the_downward_tier if {
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"package": "storefront-theme", "digest": "6053401fe5190a3153158f3173dd0f0212e3d0270be5ff30289a76495988e875"})
	r := component.audit with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	r.verdict == "drifts"
	error_rules(r)["gate/dependency-hierarchy-violation"]
}

# An unreadable manifest and a drift together report both,
# honestly — the verdict ladder names the worse one.
test_audit_reports_the_unreadable_and_the_drift_together if {
	p := fixture.with_dependency_field(fixture.with_field(fixture.package_manifest, {"version": null}), "platform-baseline", {"package": "payments-legacy"})
	r := component.audit with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	r.verdict == "unreadable"
	error_rules(r)["package/version-required"]
	error_rules(r)["gate/dependency-unresolved"]
}

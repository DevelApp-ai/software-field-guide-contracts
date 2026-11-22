# The composed IAM-broker scope audit, tested as the browser
# playground calls it: one evaluation, the whole answer — the
# broker grant document validated, the grants joined against the
# package manifest, one verdict, one findings list, the grant cards
# alongside. The findings of the two analyzers are sets, so a shared
# condition is reported once, not twice.
package broker.audit_test

import rego.v1

import data.broker

import data.broker.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the composed control ------------------------------------------------------

test_control_audit_is_consistent_with_the_grant_cards if {
	r := broker.audit with input as fixture.gate_input(fixture.package_manifest, fixture.broker_doc)
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
	count(r.grants) == 2
}

# --- drifts reach the audit as drifts ----------------------------------------------

test_audit_refuses_an_unresolved_component if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"component": "storefront-theme"})
	r := broker.audit with input as fixture.gate_input(fixture.package_manifest, b)
	not r.valid
	error_rules(r)["gate/component-unresolved"]
	r.verdict == "drifts"
	count(r.grants) == 2
}

test_audit_refuses_a_digest_drift if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"digest": "a75f47bd3c7d7f1bcaf4a76a163ed589b5f26708b44996a37ee7f789e9c31c15"})
	r := broker.audit with input as fixture.gate_input(fixture.package_manifest, b)
	not r.valid
	error_rules(r)["gate/digest-drift"]
	r.verdict == "drifts"
}

# --- unreadable inputs render their cards, verdict and all --------------------------

test_audit_refuses_a_wildcard_but_renders_the_card if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": ["*"]})
	r := broker.audit with input as fixture.gate_input(fixture.package_manifest, b)
	not r.valid
	error_rules(r)["grant/action-wildcard"]
	r.verdict == "unreadable"
	count(r.grants) == 2
	r.grants[0].verdict == "drifts"
}

test_audit_refuses_an_expired_grant_but_renders_the_card if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"expires": "2026-10-01"})
	r := broker.audit with input as fixture.gate_input(fixture.package_manifest, b)
	error_rules(r)["grant/expires-in-past"]
	r.verdict == "unreadable"
	r.grants[0].verdict == "drifts"
	r.grants[1].verdict == "consistent"
}

test_audit_refuses_an_undeclared_principal_but_renders_the_card if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"principal": "quarantine-scanner"})
	r := broker.audit with input as fixture.gate_input(fixture.package_manifest, b)
	error_rules(r)["grant/principal-undeclared"]
	r.verdict == "unreadable"
	r.grants[0].verdict == "drifts"
}

# --- the sets: shared conditions reported once ---------------------------------------

test_audit_reports_a_broken_manifest_once if {
	m := fixture.with_field(fixture.package_manifest, {"artifactDigest": "5766fab"})
	r := broker.audit with input as fixture.gate_input(m, fixture.broker_doc)
	count([f | some f in r.findings; f.rule == "artifact/digest-malformed"]) == 1
	r.verdict == "unreadable"
}

test_audit_reports_missing_documents_once if {
	r := broker.audit with input as {"today": fixture.today}
	count([f | some f in r.findings; f.rule == "package/missing"]) == 1
	count([f | some f in r.findings; f.rule == "broker/missing"]) == 1
	count([f | some f in r.findings; f.rule == "input/invalid"]) == 0
	r.verdict == "unreadable"
	r.grants == []
}

test_audit_reports_a_broken_clock_once if {
	r := broker.audit with input as object.union(fixture.control_input, {"today": "2026-13-01"})
	count([f | some f in r.findings; f.rule == "input/today-invalid"]) == 1
	r.verdict == "unreadable"
}

# --- the boundary with #101: the composure, pinned -----------------------------------

# The gate composes on the component package conformance validator
# without reading its judgment: a manifest whose signatures and
# stamps #101 would reject, but whose join fields are readable, is
# answered by this gate on the join alone.
test_audit_joins_without_reading_the_components_conformance if {
	m := fixture.with_field(fixture.package_manifest, {"signature": null})
	r := broker.audit with input as fixture.gate_input(m, fixture.broker_doc)

	# The broker gate issues no finding about the manifest's
	# signature: that is the component gate's word, not this one's.
	count([f | some f in r.findings; f.rule == "signature/signature-required"]) == 0
	r.verdict == "consistent"
}

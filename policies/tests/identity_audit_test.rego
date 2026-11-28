package identity.audit_test

import rego.v1

import data.identity

import data.identity.fixture

error_rules(r) := {f.rule | f := r.findings[_]; f.severity == "error"}

card(r, item) := c if {
	some c in r.cards
	c.item == item
}

with_extra_reference(manifest_doc, name, row) := object.union(manifest_doc, {"identities": [identity_extend(i, name, row) |
	some i in manifest_doc.identities
]})

identity_extend(i, name, row) := object.union(i, {"references": array.concat(i.references, [row])}) if object.get(i, "name", null) == name

identity_extend(i, name, row) := i if object.get(i, "name", null) != name

# --- the control: one audit, the whole answer ---------------------------------

test_control_audit_is_consistent if {
	r := identity.audit with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_control_audit_shape if {
	r := identity.audit with input as fixture.control_input
	object.keys(r) == {"valid", "findings", "cards", "verdict"}
	count(r.cards) == 4
}

test_control_audit_cards_carry_the_board if {
	r := identity.audit with input as fixture.control_input
	card(r, "checkout-worker/settlement-signing-key").area == "references"
	card(r, "checkout-worker/settlement-signing-key").verdict == "consistent"
}

# --- the composed union: shared conditions report once ------------------------

# The manifest's own findings are sets in both analyzers, so a
# manifest stamped wrong is reported by the audit exactly once —
# the union deduplicates, not double-counts.
test_audit_reports_an_unversioned_manifest_once if {
	m := fixture.with_field(fixture.manifest, {"version": null})
	r := identity.audit with input as fixture.gate_input(m, fixture.catalog)
	count([f | some f in r.findings; f.rule == "manifest/version-required"]) == 1
	r.verdict == "unreadable"
}

test_audit_reports_a_missing_manifest_once if {
	r := identity.audit with input as object.remove(fixture.control_input, {"manifest"})
	count([f | some f in r.findings; f.rule == "manifest/missing"]) == 1
	r.verdict == "unreadable"
}

test_audit_reports_a_wildcard_scope_once if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"scope": "*"})
	r := identity.audit with input as fixture.gate_input(m, fixture.catalog)
	count([f | some f in r.findings; f.rule == "reference/scope-wildcard"]) == 1
	r.verdict == "unreadable"
}

test_audit_reports_a_secret_without_a_rotation_clock_once if {
	c := fixture.with_secret_field(fixture.catalog, "payments-api-key", {"rotatedOn": null})
	r := identity.audit with input as fixture.gate_input(fixture.manifest, c)
	count([f | some f in r.findings; f.rule == "secret/rotated-on-required"]) == 1
	r.verdict == "unreadable"
}

# --- the drifts reach the composed verdict -------------------------------------

test_audit_drifts_on_a_phantom_reference if {
	m := with_extra_reference(fixture.manifest, "billing-exporter", {"secret": "integration-webhook-secret", "scope": "integrations:send", "since": "2026-10-01"})
	r := identity.audit with input as fixture.gate_input(m, fixture.catalog)
	count(r.findings) == 1
	error_rules(r)["gate/reference-unresolved"]
	r.verdict == "drifts"
}

test_audit_drifts_on_an_undeclared_identity if {
	c := fixture.with_secret_field(fixture.catalog, "billing-read-token", {"consumers": []})
	r := identity.audit with input as fixture.gate_input(fixture.manifest, c)
	count(r.findings) == 1
	error_rules(r)["gate/identity-undeclared"]
	r.verdict == "drifts"
}

test_audit_drifts_on_a_scope_mismatch if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"scope": "payments:refunds"})
	r := identity.audit with input as fixture.gate_input(m, fixture.catalog)
	count(r.findings) == 1
	error_rules(r)["gate/scope-mismatch"]
	r.verdict == "drifts"
}

test_audit_drifts_on_an_overdue_clock if {
	c := fixture.with_secret_field(fixture.catalog, "settlement-signing-key", {"rotatedOn": "2026-07-01"})
	r := identity.audit with input as fixture.gate_input(fixture.manifest, c)
	count(r.findings) == 1
	error_rules(r)["gate/rotation-overdue"]
	r.verdict == "drifts"
}

# --- the ladder reaches the audit verdict honestly ------------------------------

test_audit_verdict_is_unreadable_when_the_clock_is_not_a_date if {
	r := identity.audit with input as object.union(object.remove(fixture.control_input, {"today"}), {"today": "not a date"})
	not r.valid
	r.verdict == "unreadable"
}

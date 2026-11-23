package identity.gate_test

import rego.v1

import data.identity

import data.identity.fixture

error_rules(r) := {f.rule | f := r.findings[_]; f.severity == "error"}

card(r, item) := c if {
	some c in r.cards
	c.item == item
}

# --- override helpers -------------------------------------------------------

# Append one reference row to one identity, by name.
with_extra_reference(manifest_doc, name, row) := object.union(manifest_doc, {"identities": [identity_extend(i, name, row) |
	some i in manifest_doc.identities
]})

identity_extend(i, name, row) := object.union(i, {"references": array.concat(i.references, [row])}) if object.get(i, "name", null) == name

identity_extend(i, name, row) := i if object.get(i, "name", null) != name

# --- the control: every reference vouched for, live clocks ---------------------

test_control_gate_passes_and_renders_consistent if {
	r := identity.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_control_renders_one_card_per_declared_reference if {
	r := identity.gate with input as fixture.control_input
	count(r.cards) == 4
	r.cards[0].area == "references"
}
test_control_card_verdicts_are_all_consistent if {
	r := identity.gate with input as fixture.control_input
	count([c | some c in r.cards; c.verdict == "consistent"]) == 4
}
test_control_card_details_carry_the_clock if {
	r := identity.gate with input as fixture.control_input
	card(r, "checkout-web/payments-api-key").detail == "the catalog admits 'checkout-web' to 'payments-api-key' at scope 'payments:charges', rotated 2026-09-30 with 70 days left on the clock (manifest.yaml, catalog.yaml)"
	card(r, "billing-exporter/billing-read-token").detail == "the catalog admits 'billing-exporter' to 'billing-read-token' at scope 'billing:read', rotated 2026-09-05 with 45 days left on the clock (manifest.yaml, catalog.yaml)"
}

# --- drift 1: the reference the catalog cannot vouch for ----------------------

test_phantom_reference_fails_the_gate if {
	tm := with_extra_reference(fixture.manifest, "billing-exporter", {"secret": "integration-webhook-secret", "scope": "integrations:send", "since": "2026-10-01"})
	r := identity.gate with input as fixture.gate_input(m, fixture.catalog)
	not r.valid
	error_rules(r)["gate/reference-unresolved"]
	r.verdict == "drifts"
}

test_phantom_reference_bites_exactly_once if {
	m := with_extra_reference(fixture.manifest, "billing-exporter", {"secret": "integration-webhook-secret", "scope": "integrations:send", "since": "2026-10-01"})
	r := identity.gate with input as fixture.gate_input(m, fixture.catalog)
	count(r.findings) == 1
}

test_phantom_reference_cites_both_files if {
	m := with_extra_reference(fixture.manifest, "billing-exporter", {"secret": "integration-webhook-secret", "scope": "integrations:send", "since": "2026-10-01"})
	r := identity.gate with input as fixture.gate_input(m, fixture.catalog)
	some f in r.findings
	f.rule == "gate/reference-unresolved"
	contains(f.message, "manifest.yaml")
	contains(f.message, "catalog.yaml")
}

test_phantom_reference_card_renders_drifts if {
	m := with_extra_reference(fixture.manifest, "billing-exporter", {"secret": "integration-webhook-secret", "scope": "integrations:send", "since": "2026-10-01"})
	r := identity.gate with input as fixture.gate_input(m, fixture.catalog)
	count(r.cards) == 5
	card(r, "billing-exporter/integration-webhook-secret").verdict == "drifts"
	card(r, "billing-exporter/integration-webhook-secret").detail == "the catalog does not vouch for this reference (manifest.yaml, catalog.yaml)"
	card(r, "checkout-web/payments-api-key").verdict == "consistent"
}

# --- drift 2: the identity the catalog never admitted -------------------------

test_undeclared_identity_fails_the_gate if {
	c := fixture.with_secret_field(fixture.catalog, "billing-read-token", {"consumers": []})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	not r.valid
	error_rules(r)["gate/identity-undeclared"]
	r.verdict == "drifts"
}

test_undeclared_identity_bites_exactly_once_and_cites_both_files if {
	c := fixture.with_secret_field(fixture.catalog, "billing-read-token", {"consumers": []})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	count(r.findings) == 1
	f := r.findings[0]
	contains(f.message, "manifest.yaml")
	contains(f.message, "catalog.yaml")
}

test_undeclared_identity_card_renders_drifts if {
	c := fixture.with_secret_field(fixture.catalog, "billing-read-token", {"consumers": []})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	card(r, "billing-exporter/billing-read-token").verdict == "drifts"
	card(r, "billing-exporter/billing-read-token").detail == "the catalog names the secret 'billing-read-token' but not the identity 'billing-exporter' among its consumers (manifest.yaml, catalog.yaml)"
	card(r, "checkout-web/payments-api-key").verdict == "consistent"
}

# --- drift 3: the scope the catalog never wrote -------------------------------

test_scope_mismatch_fails_the_gate if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"scope": "payments:refunds"})
	r := identity.gate with input as fixture.gate_input(m, fixture.catalog)
	not r.valid
	error_rules(r)["gate/scope-mismatch"]
	r.verdict == "drifts"
}

test_scope_mismatch_bites_exactly_once_and_cites_both_files if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"scope": "payments:refunds"})
	r := identity.gate with input as fixture.gate_input(m, fixture.catalog)
	count(r.findings) == 1
	f := r.findings[0]
	contains(f.message, "manifest.yaml")
	contains(f.message, "catalog.yaml")
}

test_scope_mismatch_card_renders_drifts if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"scope": "payments:refunds"})
	r := identity.gate with input as fixture.gate_input(m, fixture.catalog)
	card(r, "checkout-web/payments-api-key").verdict == "drifts"
	card(r, "checkout-web/payments-api-key").detail == "the reference claims scope 'payments:refunds', the catalog grants 'payments:charges' (manifest.yaml, catalog.yaml)"
}

# --- drift 4: the rotation clock that ran out ---------------------------------

test_rotation_overdue_fails_the_gate if {
	c := fixture.with_secret_field(fixture.catalog, "settlement-signing-key", {"rotatedOn": "2026-07-01"})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	not r.valid
	error_rules(r)["gate/rotation-overdue"]
	r.verdict == "drifts"
}

test_rotation_overdue_bites_exactly_once_and_cites_the_clock if {
	c := fixture.with_secret_field(fixture.catalog, "settlement-signing-key", {"rotatedOn": "2026-07-01"})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	count(r.findings) == 1
	f := r.findings[0]
	f.rule == "gate/rotation-overdue"
	contains(f.message, "2026-07-01")
	contains(f.message, "60-day clock")
	contains(f.message, "catalog.yaml")
}

test_rotation_overdue_card_renders_drifts if {
	c := fixture.with_secret_field(fixture.catalog, "settlement-signing-key", {"rotatedOn": "2026-07-01"})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	card(r, "checkout-worker/settlement-signing-key").verdict == "drifts"
	card(r, "checkout-worker/settlement-signing-key").detail == "the secret 'settlement-signing-key' is 51 days past its rotation clock, last rotated 2026-07-01 (manifest.yaml, catalog.yaml)"
	card(r, "checkout-worker/payments-api-key").verdict == "consistent"
}

# --- the reserved catalog secret is availability, not a drift ------------------

test_unconsumed_secret_passes_the_gate if {
	r := identity.gate with input as fixture.control_input
	count(r.findings) == 0
	count([c | some c in r.cards; contains(c.item, "reportstore-readonly")]) == 0
}

# --- a document the gate cannot read is unreadable, honestly ------------------

test_missing_catalog_is_unreadable_not_drifts if {
	r := identity.gate with input as object.remove(fixture.control_input, {"catalog"})
	not r.valid
	error_rules(r)["catalog/missing"]
	r.verdict == "unreadable"
}

test_stale_catalog_is_unreadable if {
	c := fixture.with_field(fixture.catalog, {"reviewedOn": "2024-10-01"})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	error_rules(r)["catalog/reviewed-stale"]
	r.verdict == "unreadable"
}

test_unknown_kind_is_unreadable if {
	c := fixture.with_secret_field(fixture.catalog, "billing-read-token", {"kind": "post-it-note"})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	error_rules(r)["secret/kind-unknown"]
	r.verdict == "unreadable"
}

test_wildcard_scope_stays_a_validation_story if {
	m := fixture.with_reference_field(fixture.manifest, "checkout-web", "payments-api-key", {"scope": "*"})
	r := identity.gate with input as fixture.gate_input(m, fixture.catalog)
	error_rules(r)["reference/scope-wildcard"]
	count([f | some f in r.findings; f.rule == "gate/scope-mismatch"]) == 0
	r.verdict == "unreadable"
}

test_missing_rotation_clock_is_unreadable if {
	c := fixture.with_secret_field(fixture.catalog, "reportstore-readonly", {"rotatedOn": null})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	count([f | some f in r.findings; f.rule == "secret/rotated-on-required"]) == 1
	r.verdict == "unreadable"
}

test_unreadable_clock_keeps_the_card_on_the_board if {
	c := fixture.with_secret_field(fixture.catalog, "billing-read-token", {"rotatedOn": null})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	some f in r.findings
	f.rule == "secret/rotated-on-required"
	contains(f.message, "billing-read-token")
	card(r, "billing-exporter/billing-read-token").verdict == "drifts"
	card(r, "billing-exporter/billing-read-token").detail == "the catalog admits 'billing-exporter' to 'billing-read-token', but its rotation clock is not readable — see the findings (manifest.yaml, catalog.yaml)"
}

test_invalid_max_age_is_unreadable if {
	c := fixture.with_secret_field(fixture.catalog, "payments-api-key", {"maxAgeDays": 0})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	error_rules(r)["secret/max-age-invalid"]
	r.verdict == "unreadable"
}

test_consumers_must_be_an_array_of_names if {
	c := fixture.with_secret_field(fixture.catalog, "payments-api-key", {"consumers": "checkout-web"})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	count([f | some f in r.findings; f.rule == "secret/consumers-must-be-array"]) == 1
	r.verdict == "unreadable"
}

test_duplicate_consumer_bites_exactly_once if {
	c := fixture.with_secret_field(fixture.catalog, "settlement-signing-key", {"consumers": ["checkout-worker", "checkout-worker"]})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	count([f | some f in r.findings; f.rule == "secret/consumer-duplicate"]) == 1
	r.verdict == "unreadable"
}

test_zero_day_clock_is_never_overdue if {
	c := fixture.with_secret_field(fixture.catalog, "reportstore-readonly", {"maxAgeDays": 0})
	r := identity.gate with input as fixture.gate_input(fixture.manifest, c)
	count([f | some f in r.findings; f.rule == "gate/rotation-overdue"]) == 0
}

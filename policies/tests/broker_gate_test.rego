# The IAM-broker scope gate, tested as the join it is: the manifest
# the grants resolve against, the two drifts the gate knows by name,
# and the grant cards the playground renders. The gate composes on
# the component package conformance validator (#101): a test pins
# the boundary by breaking only what the join reads — the grants
# still resolve against a manifest whose signature the broker never
# checks, because that is #101's word.
package broker.gate_test

import rego.v1

import data.broker

import data.broker.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

# --- the control -------------------------------------------------------------

test_control_gate_is_consistent if {
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, fixture.broker_doc)
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_control_renders_exactly_two_cards if {
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, fixture.broker_doc)
	count(r.grants) == 2
	card := r.grants[0]
	card.principal == "storefront-build"
	card.component == "payments-checkout"
	card.verdict == "consistent"
	card_two := r.grants[1]
	card_two.principal == "payments-build"
	card_two.component == "platform-baseline"
	card_two.verdict == "consistent"
}

# A grant resolves against the package's pinned dependency, not
# only against the package's own entry — that resolution is the
# join's substance.
test_dependencies_resolve_grants if {
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, fixture.broker_doc)
	count([f | some f in r.findings; f.rule == "gate/component-unresolved"]) == 0
	count([f | some f in r.findings; f.rule == "gate/digest-drift"]) == 0
}

# --- the manifest at the gate ---------------------------------------------------

test_the_manifest_is_required if {
	r := broker.gate with input as {
		"broker": fixture.broker_doc,
		"today": fixture.today,
		"brokerFile": fixture.broker_file,
	}
	error_rules(r)["package/missing"]
	r.verdict == "unreadable"
	r.grants == []
}

test_manifest_component_name_required if {
	m := fixture.with_field(fixture.package_manifest, {"component": ""})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	error_rules(r)["component/name-required"]
	r.verdict == "unreadable"
	r.grants == []
}

test_manifest_digest_required if {
	m := fixture.with_field(fixture.package_manifest, {"artifactDigest": null})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	error_rules(r)["artifact/digest-required"]
	r.verdict == "unreadable"
}

test_manifest_digest_malformed if {
	m := fixture.with_field(fixture.package_manifest, {"artifactDigest": "5766fab"})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	error_rules(r)["artifact/digest-malformed"]
	r.verdict == "unreadable"
}

test_dependencies_must_be_an_array if {
	m := fixture.with_field(fixture.package_manifest, {"dependencies": "nope"})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	error_rules(r)["package/dependencies-must-be-array"]
}

test_dependency_rows_must_be_objects if {
	m := fixture.with_field(fixture.package_manifest, {"dependencies": ["nope"]})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	error_rules(r)["package/dependency-must-be-object"]
}

test_dependency_names_are_required if {
	m := fixture.with_field(fixture.package_manifest, {"dependencies": [{"package": "", "digest": "d6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44"}]})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	error_rules(r)["package/dependency-package-required"]
}

test_dependency_digests_are_required if {
	m := fixture.with_field(fixture.package_manifest, {"dependencies": [{"package": "platform-baseline"}]})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	error_rules(r)["package/dependency-digest-required"]
}

test_dependency_digests_must_be_real_digests if {
	m := fixture.with_field(fixture.package_manifest, {"dependencies": [{"package": "platform-baseline", "digest": "d6545bd"}]})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	error_rules(r)["package/dependency-digest-malformed"]
}

# Absent dependencies are honest: the package pins none, so only
# the package's own entry resolves — the grant on the pinned
# baseline becomes unresolved, and the gate says so as a drift.
test_absent_dependencies_are_honest if {
	m := fixture.replace_field(fixture.package_manifest, {"dependencies": null})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	count([f | some f in r.findings; f.rule == "package/dependencies-must-be-array"]) == 0
	error_rules(r)["gate/component-unresolved"]
	r.verdict == "drifts"
}

# --- the two drifts, named ---------------------------------------------------------

test_the_unresolved_grant_drifts if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"component": "storefront-theme"})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	error_rules(r)["gate/component-unresolved"]
	count([f | some f in r.findings; f.rule == "gate/digest-drift"]) == 0
	r.verdict == "drifts"
}

test_the_digest_drift if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"digest": "a75f47bd3c7d7f1bcaf4a76a163ed589b5f26708b44996a37ee7f789e9c31c15"})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	error_rules(r)["gate/digest-drift"]
	count([f | some f in r.findings; f.rule == "gate/component-unresolved"]) == 0
	r.verdict == "drifts"
}

# --- the cards: only the join needs to be readable ----------------------------------

# A stamp-shaped failure (an expired grant) makes the gate
# unreadable, but the join can still be asked: the cards render, and
# the expired grant's card drifts with its finding named.
test_an_expired_grant_renders_a_drifting_card if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"expires": "2026-10-01"})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	r.verdict == "unreadable"
	count(r.grants) == 2
	card := r.grants[0]
	card.principal == "storefront-build"
	card.verdict == "drifts"
	contains(card.detail, "expired on 2026-10-01")
}

# An expired grant does not hide the second grant's consistency.
test_the_second_card_stays_consistent if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"expires": "2026-10-01"})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	r.grants[1].verdict == "consistent"
}

test_the_wildcard_grant_renders_a_drifting_card if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": ["*"]})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	r.verdict == "unreadable"
	count(r.grants) == 2
	card := r.grants[0]
	card.verdict == "drifts"
	contains(card.detail, "wildcard action")
}

test_the_undeclared_principal_renders_a_drifting_card if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"principal": "quarantine-scanner"})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	r.verdict == "unreadable"
	card := r.grants[0]
	card.verdict == "drifts"
	contains(card.detail, "never declared")
}

test_an_actions_row_that_is_not_an_array_renders_a_drifting_card if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"actions": "pull"})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	r.verdict == "unreadable"
	card := r.grants[0]
	card.verdict == "drifts"
	contains(card.detail, "not an array")
}

test_an_expired_grant_card_cites_the_clock_honestly if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"expires": "2026-02-30"})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	card := r.grants[0]
	card.verdict == "drifts"
	contains(card.detail, "not a real calendar date")
}

# The join outranks the grant's own scope on the card: an unresolved
# component is named before an expired clock.
test_the_join_is_named_first_on_the_card if {
	b := fixture.with_grant_field(fixture.broker_doc, 0, {"component": "storefront-theme", "expires": "2026-10-01"})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	card := r.grants[0]
	card.verdict == "drifts"
	contains(card.detail, "neither packages nor pins")
}

# A manifest too broken to ask the join suppresses the cards, not
# the findings.
test_a_broken_manifest_suppresses_the_cards if {
	m := fixture.with_field(fixture.package_manifest, {"component": null})
	r := broker.gate with input as fixture.gate_input(m, fixture.broker_doc)
	error_rules(r)["component/name-required"]
	r.grants == []
}

# A broker document too broken to count its grants suppresses the
# cards as well.
test_a_broken_broker_document_suppresses_the_cards if {
	b := fixture.with_field(fixture.broker_doc, {"grants": "nope"})
	r := broker.gate with input as fixture.gate_input(fixture.package_manifest, b)
	error_rules(r)["grants/must-be-array"]
	r.grants == []
}

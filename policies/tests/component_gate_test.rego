package component.gate_test

import rego.v1

import data.component

import data.component.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

card(r, area, item) := c if {
	some c in r.cards
	c.area == area
	c.item == item
}

# --- the control: one registered package, its pins answered for ----------------

test_control_gate_passes_and_renders_consistent if {
	r := component.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_control_renders_one_card_per_judged_item if {
	r := component.gate with input as fixture.control_input
	count(r.cards) == 2
	r.cards[0].area == "package"
	r.cards[1].area == "dependencies"
}

test_control_card_verdicts_are_all_consistent if {
	r := component.gate with input as fixture.control_input
	count([c | some c in r.cards; c.verdict == "consistent"]) == 2
}

test_control_card_details if {
	r := component.gate with input as fixture.control_input
	card(r, "package", "payments-checkout").detail == "v1.4.0 registered, publishing the digest the registry recorded (package.yaml, registry.yaml)"
	card(r, "dependencies", "platform-baseline").detail == "pinned to a digest the registry records for 'platform-baseline' (package.yaml, registry.yaml)"
}

# --- the five drifts: conformance failures, the gate refuses ------------------

test_unregistered_package_fails_the_gate if {
	p := fixture.with_field(fixture.package_manifest, {"version": "1.5.0"})
	r := component.gate with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	error_rules(r)["gate/package-unregistered"]
	r.verdict == "drifts"
}

test_unregistered_package_cites_both_files if {
	p := fixture.with_field(fixture.package_manifest, {"version": "1.5.0"})
	r := component.gate with input as fixture.gate_input(p, fixture.registry)
	some f in r.findings
	f.rule == "gate/package-unregistered"
	contains(f.message, "package.yaml")
	contains(f.message, "registry.yaml")
}

# A swapped artifact with a stale signature reports both,
# honestly: the recorded evidence is no longer internally
# consistent, so the verdict is unreadable, not drifts.
test_digest_drift_with_a_stale_signature_reports_both if {
	p := fixture.with_field(fixture.package_manifest, {"artifactDigest": "4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80"})
	r := component.gate with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	error_rules(r)["signature/digest-mismatch"]
	error_rules(r)["gate/package-digest-drift"]
	r.verdict == "unreadable"
}

# A re-signed drifted artifact bites exactly once at the join: the
# evidence is consistent, the registry is stale, the verdict is
# drifts.
test_digest_drift_catches_the_signature_too if {
	p := fixture.with_field(fixture.package_manifest, {"artifactDigest": "4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80", "signature": {"keyId": "key-2026-q4", "signedDigest": "4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80"}})
	r := component.gate with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	error_rules(r)["gate/package-digest-drift"]
	count([f | some f in r.findings; startswith(f.rule, "gate/")]) == 1
	r.verdict == "drifts"
}

test_unresolved_dependency_fails_the_gate if {
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"package": "payments-legacy"})
	r := component.gate with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	error_rules(r)["gate/dependency-unresolved"]
	r.verdict == "drifts"
}

test_stale_pin_fails_the_gate if {
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"digest": "aaf1965eeee9f4c7eaf29bbb5b32eb477629a35c41d21dd75037af59b0ee8e1c"})
	r := component.gate with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	error_rules(r)["gate/dependency-digest-mismatch"]
	r.verdict == "drifts"
}

# The tier ladder is one-way: a customer-tier package depending on
# a project-tier package points down.
test_customer_tier_on_project_tier_fails_the_gate if {
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"package": "storefront-theme", "digest": "6053401fe5190a3153158f3173dd0f0212e3d0270be5ff30289a76495988e875"})
	r := component.gate with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	error_rules(r)["gate/dependency-hierarchy-violation"]
	r.verdict == "drifts"
}

test_customer_tier_on_customer_tier_is_consistent if {
	g := fixture.with_registry_row_field(fixture.registry, "storefront-theme", {"component": "checkout-shared", "version": "0.9.0", "hierarchy": "customer"})
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"package": "checkout-shared", "digest": "6053401fe5190a3153158f3173dd0f0212e3d0270be5ff30289a76495988e875"})
	r := component.gate with input as fixture.gate_input(p, g)
	r.valid == true
	r.verdict == "consistent"
}

test_drift_card_renders_drifts if {
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"package": "payments-legacy"})
	r := component.gate with input as fixture.gate_input(p, fixture.registry)
	card(r, "dependencies", "payments-legacy").verdict == "drifts"
	card(r, "dependencies", "payments-legacy").detail == "resolves to no package in the registry (package.yaml, registry.yaml)"
}

# --- the registry at the gate ---------------------------------------------------

test_registry_missing_fails_the_gate if {
	r := component.gate with input as object.remove(fixture.control_input, {"registry"})
	not r.valid
	error_rules(r)["registry/missing"]
	r.verdict == "unreadable"
}

test_registry_version_required if {
	g := fixture.with_field(fixture.registry, {"version": null})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/version-required"]
	r.verdict == "unreadable"
}

test_registry_reviewed_in_future if {
	g := fixture.with_field(fixture.registry, {"reviewedOn": "2026-12-01"})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/reviewed-in-future"]
}

test_registry_reviewed_stale if {
	g := fixture.with_field(fixture.registry, {"reviewedOn": "2024-10-01"})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/reviewed-stale"]
}

test_registry_owner_required if {
	g := fixture.with_field(fixture.registry, {"owner": ""})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/owner-required"]
}

test_registry_packages_must_be_array if {
	g := fixture.with_field(fixture.registry, {"packages": "payments-checkout"})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/packages-must-be-array"]
}

test_registry_row_must_be_object if {
	g := fixture.with_field(fixture.registry, {"packages": array.concat(fixture.registry.packages, ["payments-checkout"])})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/row-must-be-object"]
}

test_registry_row_name_required if {
	g := fixture.with_registry_row_field(fixture.registry, "storefront-theme", {"component": ""})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/row-name-required"]
}

test_registry_row_version_required if {
	g := fixture.with_registry_row_field(fixture.registry, "storefront-theme", {"version": ""})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/row-version-required"]
}

test_registry_row_hierarchy_unknown if {
	g := fixture.with_registry_row_field(fixture.registry, "storefront-theme", {"hierarchy": "platform"})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/row-hierarchy-unknown"]
}

test_registry_row_digest_malformed if {
	g := fixture.with_registry_row_field(fixture.registry, "storefront-theme", {"digest": "deadbeef"})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/row-digest-malformed"]
}

test_registry_row_duplicate if {
	g := fixture.with_field(fixture.registry, {"packages": array.concat(fixture.registry.packages, [{"component": "storefront-theme", "version": "0.3.0", "hierarchy": "project", "digest": "6053401fe5190a3153158f3173dd0f0212e3d0270be5ff30289a76495988e875"}])})
	r := component.gate with input as fixture.gate_input(fixture.package_manifest, g)
	not r.valid
	error_rules(r)["registry/row-duplicate"]
}

# --- the gate re-reports the package manifest's own findings --------------------

test_gate_fails_on_a_package_without_its_version if {
	p := fixture.with_field(fixture.package_manifest, {"version": null})
	r := component.gate with input as fixture.gate_input(p, fixture.registry)
	not r.valid
	error_rules(r)["package/version-required"]
	r.verdict == "unreadable"
}

test_gate_fails_on_a_package_it_cannot_read_at_all if {
	r := component.gate with input as {
		"package": "not an object",
		"registry": fixture.registry,
		"today": fixture.today,
	}
	not r.valid
	error_rules(r)["package/missing"]
	r.verdict == "unreadable"
}

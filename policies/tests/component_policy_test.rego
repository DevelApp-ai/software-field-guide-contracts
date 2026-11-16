package component.policy_test

import rego.v1

import data.component

import data.component.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_control_package_valid if {
	r := component.validate with input as fixture.validate_input(fixture.package_manifest)
	r.valid == true
	count(r.findings) == 0
}

test_input_must_be_object if {
	r := component.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := component.validate with input as {"package": fixture.package_manifest, "today": "2026-13-01"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_package_missing if {
	r := component.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["package/missing"]
}

test_version_required if {
	p := fixture.with_field(fixture.package_manifest, {"version": null})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["package/version-required"]
}

test_reviewed_on_invalid if {
	p := fixture.with_field(fixture.package_manifest, {"reviewedOn": "10/01/2026"})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["package/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	p := fixture.with_field(fixture.package_manifest, {"reviewedOn": "2026-12-01"})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["package/reviewed-in-future"]
}

test_reviewed_stale if {
	p := fixture.with_field(fixture.package_manifest, {"reviewedOn": "2024-10-01"})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["package/reviewed-stale"]
}

test_owner_required if {
	p := fixture.with_field(fixture.package_manifest, {"owner": ""})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["package/owner-required"]
}

test_component_name_required if {
	p := fixture.with_field(fixture.package_manifest, {"component": ""})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["component/name-required"]
}

test_hierarchy_required if {
	p := fixture.with_field(fixture.package_manifest, {"hierarchy": null})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["hierarchy/required"]
}

test_hierarchy_unknown if {
	p := fixture.with_field(fixture.package_manifest, {"hierarchy": "platform"})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["hierarchy/unknown"]
}

test_artifact_digest_required if {
	p := fixture.with_field(fixture.package_manifest, {"artifactDigest": null})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["artifact/digest-required"]
}

test_artifact_digest_malformed if {
	p := fixture.with_field(fixture.package_manifest, {"artifactDigest": "not-a-digest"})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["artifact/digest-malformed"]
}

test_signature_required if {
	p := fixture.with_field(fixture.package_manifest, {"signature": null})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["signature/required"]
}

test_signature_key_required if {
	p := fixture.with_field(fixture.package_manifest, {"signature": {"keyId": "", "signedDigest": fixture.package_manifest.artifactDigest}})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["signature/key-required"]
}

test_signature_digest_required if {
	p := fixture.with_field(fixture.package_manifest, {"signature": {"keyId": "key-2026-q4", "signedDigest": ""}})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["signature/digest-required"]
}

# The conformance the validator can check honestly: the recorded
# signature signs the artifact digest the manifest publishes.
test_signature_digest_mismatch if {
	p := fixture.with_field(fixture.package_manifest, {"signature": {"keyId": "key-2026-q4", "signedDigest": "4ea0ac5c92c4939f8902c75406b4f583942f922272cfc7b94eac70abdab97e80"}})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["signature/digest-mismatch"]
}

test_attestation_required if {
	p := fixture.with_field(fixture.package_manifest, {"attestation": null})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["attestation/required"]
}

test_attestation_statement_required if {
	p := fixture.with_field(fixture.package_manifest, {"attestation": {"statement": "", "by": "release pipeline"}})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["attestation/statement-required"]
}

test_attestation_by_required if {
	p := fixture.with_field(fixture.package_manifest, {"attestation": {"statement": "built by the pipeline", "by": ""}})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["attestation/by-required"]
}

test_provenance_required if {
	p := fixture.with_field(fixture.package_manifest, {"provenance": null})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["provenance/required"]
}

test_provenance_source_required if {
	p := fixture.with_field(fixture.package_manifest, {"provenance": {"source": "", "commit": "9f31c0e"}})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["provenance/source-required"]
}

test_provenance_commit_required if {
	p := fixture.with_field(fixture.package_manifest, {"provenance": {"source": "payments/checkout.git", "commit": ""}})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["provenance/commit-required"]
}

test_dependencies_must_be_array if {
	p := fixture.with_field(fixture.package_manifest, {"dependencies": "platform-baseline"})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["dependencies/must-be-array"]
}

test_dependencies_row_must_be_object if {
	p := fixture.with_field(fixture.package_manifest, {"dependencies": array.concat(fixture.package_manifest.dependencies, ["platform-baseline"])})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["dependencies/row-must-be-object"]
}

test_dependency_name_required if {
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"package": ""})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["dependency/name-required"]
}

test_dependency_digest_required if {
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"digest": ""})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["dependency/digest-required"]
}

test_dependency_digest_malformed if {
	p := fixture.with_dependency_field(fixture.package_manifest, "platform-baseline", {"digest": "deadbeef"})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["dependency/digest-malformed"]
}

test_dependency_duplicate if {
	p := fixture.with_field(fixture.package_manifest, {"dependencies": array.concat(fixture.package_manifest.dependencies, [{"package": "platform-baseline", "digest": "d6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44"}])})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["dependency/duplicate"]
}

# The tier is a promise: the general-tier baseline everything else
# builds on depends on nothing.
test_general_tier_declaring_a_dependency_is_refused if {
	p := fixture.with_field(fixture.package_manifest, {"hierarchy": "general"})
	r := component.validate with input as fixture.validate_input(p)
	not r.valid
	error_rules(r)["dependency/general-forbidden"]
}

test_general_tier_with_no_dependencies_is_valid if {
	p := fixture.with_field(fixture.with_field(fixture.package_manifest, {"hierarchy": "general"}), {"dependencies": []})
	r := component.validate with input as fixture.validate_input(p)
	r.valid == true
	count(r.findings) == 0
}

# --- lib parity: the date helpers are a verbatim copy of the estate lib ------

test_epoch_is_day_zero if {
	component.lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	component.lib.date_to_days("2026-10-20") - component.lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not component.lib.is_valid_date("2026-02-30")
}

# Shared fixture for the component tests: one small, valid component
# estate after the component-package chapter's worked example — the
# payments team's customer-tier checkout package, registered at
# v1.4.0 with the digest it publishes, pinning one dependency on the
# platform team's general-tier baseline at the digest the registry
# records. The registry also carries a project-tier row so the tier
# ladder is seeded on both sides. The dates are chosen relative to
# the CI anchor date 2026-10-20.
package component.fixture

import rego.v1

today := "2026-10-20"

package_file := "package.yaml"

registry_file := "registry.yaml"

package_manifest := {
	"component": "payments-checkout",
	"version": "1.4.0",
	"hierarchy": "customer",
	"reviewedOn": "2026-10-01",
	"owner": "Payments team",
	"artifactDigest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
	"signature": {
		"keyId": "key-2026-q4",
		"signedDigest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
	},
	"attestation": {
		"statement": "the checkout artifact was built by the release pipeline",
		"by": "release pipeline",
	},
	"provenance": {
		"source": "payments/checkout.git",
		"commit": "9f31c0e",
	},
	"dependencies": [
		{"package": "platform-baseline", "digest": "d6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44"},
	],
}

registry := {
	"version": 1,
	"reviewedOn": "2026-10-15",
	"owner": "Platform team",
	"packages": [
		{
			"component": "payments-checkout",
			"version": "1.4.0",
			"hierarchy": "customer",
			"digest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
		},
		{
			"component": "platform-baseline",
			"version": "2.1.0",
			"hierarchy": "general",
			"digest": "d6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44",
		},
		{
			"component": "storefront-theme",
			"version": "0.3.0",
			"hierarchy": "project",
			"digest": "6053401fe5190a3153158f3173dd0f0212e3d0270be5ff30289a76495988e875",
		},
	],
}

validate_input(package_doc) := {
	"package": package_doc,
	"today": today,
	"packageFile": package_file,
}

gate_input(package_doc, registry_doc) := {
	"package": package_doc,
	"registry": registry_doc,
	"today": today,
	"packageFile": package_file,
	"registryFile": registry_file,
}

control_input := gate_input(package_manifest, registry)

# --- override helpers --------------------------------------------------------
#
# The #69 lesson, applied: an array comprehension with a condition in
# the body filters, so per-element overrides go through explicit
# two-definition helpers that always answer — the row itself when it
# does not match, the patched row when it does.

# Field replacement, not merge: object.union deep-merges object values,
# so a patch that means "this object is now X" removes the key first.
replace_field(obj, patch) := object.union(object.remove(obj, object.keys(patch)), patch)

# Override one top-level field of a document.
with_field(doc, patch) := replace_field(doc, patch)

# Override one field of one dependency row, by package name.
with_dependency_field(package_doc, name, patch) := object.union(package_doc, {"dependencies": [dependency_field_override(d, name, patch) |
	some d in package_doc.dependencies
]})

dependency_field_override(d, name, patch) := replace_field(d, patch) if object.get(d, "package", null) == name

dependency_field_override(d, name, patch) := d if object.get(d, "package", null) != name

# Override one field of one registry row, by component name.
with_registry_row_field(registry_doc, component, patch) := object.union(registry_doc, {"packages": [registry_row_field_override(r, component, patch) |
	some r in registry_doc.packages
]})

registry_row_field_override(r, component, patch) := replace_field(r, patch) if object.get(r, "component", null) == component

registry_row_field_override(r, component, patch) := r if object.get(r, "component", null) != component

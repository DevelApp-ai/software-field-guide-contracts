# Shared fixture for the policy-component tests: one small, valid
# policy estate after the component-package chapter's worked
# example — the platform's catalog admitting three policy
# components (a PCI scan and a tier egress both enforced, and an
# allowed-regions audit left available to other packages), each
# versioned, signed over its digest, and bound to one exact path —
# and the payments team's customer-tier checkout package at v1.4.0
# binding the two enforced policies at the catalog's own paths. The
# allowed-regions row is unbound by design: the shared catalog is
# judged at the join, not by inventory. The dates are chosen
# relative to the CI anchor date 2026-10-20.
package policy.fixture

import rego.v1

today := "2026-10-20"

catalog_file := "catalog.yaml"

package_file := "package.yaml"

catalog := {
	"version": 1,
	"reviewedOn": "2026-10-18",
	"owner": "Platform team",
	"policies": [
		{
			"policy": "pci-scan",
			"version": "3.2.0",
			"digest": "b09dcc492429e5e410c918a3d27911639f00759d86cd5d87612a23e15e11c324",
			"signature": {
				"keyId": "key-2026-q4",
				"signedDigest": "b09dcc492429e5e410c918a3d27911639f00759d86cd5d87612a23e15e11c324",
			},
			"posture": "enforce",
			"path": "/policies/pci-scan.rego",
		},
		{
			"policy": "tier-egress",
			"version": "1.1.0",
			"digest": "54e34a23f2c451616380d3c5432537f6e7d3df96a88e3361cc2b9674f5c289fc",
			"signature": {
				"keyId": "key-2026-q4",
				"signedDigest": "54e34a23f2c451616380d3c5432537f6e7d3df96a88e3361cc2b9674f5c289fc",
			},
			"posture": "enforce",
			"path": "/policies/tier-egress.rego",
		},
		{
			"policy": "allowed-regions",
			"version": "1.0.3",
			"digest": "d52c2699e01724cc10fa923fc03b0880698070aa87db78bcb7c77100fe306480",
			"signature": {
				"keyId": "key-2026-q4",
				"signedDigest": "d52c2699e01724cc10fa923fc03b0880698070aa87db78bcb7c77100fe306480",
			},
			"posture": "audit",
			"path": "/policies/allowed-regions.rego",
		},
	],
}

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
	"policyBindings": [
		{"policy": "pci-scan", "path": "/policies/pci-scan.rego"},
		{"policy": "tier-egress", "path": "/policies/tier-egress.rego"},
	],
}

validate_input(catalog_doc) := {
	"catalog": catalog_doc,
	"today": today,
	"catalogFile": catalog_file,
}

gate_input(catalog_doc, package_doc) := {
	"catalog": catalog_doc,
	"package": package_doc,
	"today": today,
	"catalogFile": catalog_file,
	"packageFile": package_file,
}

control_input := gate_input(catalog, package_manifest)

# --- override helpers ------------------------------------------------------------
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

# Override one field of one catalog policy row, by policy name.
with_catalog_row_field(catalog_doc, policy, patch) := object.union(catalog_doc, {"policies": [catalog_row_override(x, policy, patch) |
	some x in catalog_doc.policies
]})

catalog_row_override(x, policy, patch) := replace_field(x, patch) if object.get(x, "policy", null) == policy

catalog_row_override(x, policy, patch) := x if object.get(x, "policy", null) != policy

# Drop one catalog policy row entirely, by policy name.
without_catalog_row(catalog_doc, policy) := object.union(catalog_doc, {"policies": [x |
	some x in catalog_doc.policies
	object.get(x, "policy", null) != policy
]})

# Override one field of one package binding row, by policy name.
with_binding_field(package_doc, policy, patch) := object.union(package_doc, {"policyBindings": [binding_row_override(x, policy, patch) |
	some x in package_doc.policyBindings
]})

binding_row_override(x, policy, patch) := replace_field(x, patch) if object.get(x, "policy", null) == policy

binding_row_override(x, policy, patch) := x if object.get(x, "policy", null) != policy

# Drop the package's policy bindings entirely — the honest
# bindingless package.
without_bindings(package_doc) := replace_field(package_doc, {"policyBindings": null})

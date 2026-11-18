# Shared fixture for the render-matrix tests: one small, valid
# component estate after the component-package chapter's worked
# example — the payments team's customer-tier checkout package at
# v1.4.0, publishing its artifact digest and declaring two policy
# bindings — rendered across three fabrics (an Azure region, an AWS
# region, and the on-premises vSphere estate), every fabric
# rendering the manifest's version and digest with both bindings in
# force. The dates are chosen relative to the CI anchor date
# 2026-10-20.
package matrix.fixture

import rego.v1

today := "2026-10-20"

package_file := "package.yaml"

matrix_file := "matrix.yaml"

package_manifest := {
	"component": "payments-checkout",
	"version": "1.4.0",
	"hierarchy": "customer",
	"reviewedOn": "2026-10-01",
	"owner": "Payments team",
	"artifactDigest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
	"policyBindings": [
		{"policy": "pci-scan", "path": "/policies/pci-scan.rego"},
		{"policy": "tier-egress", "path": "/policies/tier-egress.rego"},
	],
}

matrix_doc := {
	"version": 1,
	"reviewedOn": "2026-10-18",
	"owner": "Platform team",
	"component": "payments-checkout",
	"fabrics": ["azure-west-europe", "aws-eu-central", "onprem-vsphere"],
	"renders": [
		{
			"fabric": "azure-west-europe",
			"version": "1.4.0",
			"digest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
			"bindings": [
				{"policy": "pci-scan", "path": "/policies/pci-scan.rego"},
				{"policy": "tier-egress", "path": "/policies/tier-egress.rego"},
			],
		},
		{
			"fabric": "aws-eu-central",
			"version": "1.4.0",
			"digest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
			"bindings": [
				{"policy": "pci-scan", "path": "/policies/pci-scan.rego"},
				{"policy": "tier-egress", "path": "/policies/tier-egress.rego"},
			],
		},
		{
			"fabric": "onprem-vsphere",
			"version": "1.4.0",
			"digest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
			"bindings": [
				{"policy": "pci-scan", "path": "/policies/pci-scan.rego"},
				{"policy": "tier-egress", "path": "/policies/tier-egress.rego"},
			],
		},
	],
}

validate_input(matrix) := {
	"matrix": matrix,
	"today": today,
	"matrixFile": matrix_file,
}

gate_input(package_doc, matrix) := {
	"package": package_doc,
	"matrix": matrix,
	"today": today,
	"packageFile": package_file,
	"matrixFile": matrix_file,
}

control_input := gate_input(package_manifest, matrix_doc)

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

# Override one field of one fabric's render row, by fabric name.
with_render_field(matrix, fabric, patch) := object.union(matrix, {"renders": [render_field_override(x, fabric, patch) |
	some x in matrix.renders
]})

render_field_override(x, fabric, patch) := replace_field(x, patch) if object.get(x, "fabric", null) == fabric

render_field_override(x, fabric, patch) := x if object.get(x, "fabric", null) != fabric

# Drop one fabric's render row entirely, by fabric name.
without_render(matrix, fabric) := object.union(matrix, {"renders": [x |
	some x in matrix.renders
	object.get(x, "fabric", null) != fabric
]})

# Override the bindings of one fabric's render row, wholesale.
with_render_bindings(matrix, fabric, bindings) := with_render_field(matrix, fabric, {"bindings": bindings})

# Override one binding row of one fabric's render, by policy name.
with_binding_field(matrix, fabric, policy, patch) := object.union(matrix, {"renders": [binding_field_override(x, fabric, policy, patch) |
	some x in matrix.renders
]})

binding_field_override(x, fabric, policy, patch) := object.union(x, {"bindings": [binding_row_override(b, policy, patch) |
	some b in object.get(x, "bindings", [])
]}) if object.get(x, "fabric", null) == fabric

binding_field_override(x, fabric, policy, patch) := x if object.get(x, "fabric", null) != fabric

binding_row_override(b, policy, patch) := replace_field(b, patch) if object.get(b, "policy", null) == policy

binding_row_override(b, policy, patch) := b if object.get(b, "policy", null) != policy

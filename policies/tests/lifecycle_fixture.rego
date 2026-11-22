# Shared fixture for the component lifecycle tests: one small, valid
# component estate after the component-package chapter's worked
# example — the payments team's customer-tier checkout package at
# v1.4.0, publishing its artifact digest — with the lifecycle record
# that tracks it: the bake that produced its image at the digest it
# publishes (2026-09-30), the patch folded in from
# payments/checkout.git at commit 9f31c0e (2026-10-08), and the
# upgrade to the rehearsed rollback (2026-10-15, rehearsed the day
# before it was recorded) — a record reviewed 2026-10-18 with every
# transition already on it. The dates are chosen relative to the CI
# anchor date 2026-10-20.
package lifecycle.fixture

import rego.v1

today := "2026-10-20"

lifecycle_file := "lifecycle.yaml"

package_file := "package.yaml"

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
		{
			"package": "platform-baseline",
			"digest": "d6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44",
		},
	],
	"policyBindings": [
		{
			"policy": "pci-scan",
			"path": "/policies/pci-scan.rego",
		},
		{
			"policy": "tier-egress",
			"path": "/policies/tier-egress.rego",
		},
	],
}

record_doc := {
	"version": 1,
	"reviewedOn": "2026-10-18",
	"owner": "Payments team",
	"component": "payments-checkout",
	"transitions": [
		{
			"type": "bake",
			"recordedOn": "2026-09-30",
			"imageDigest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
		},
		{
			"type": "patch",
			"recordedOn": "2026-10-08",
			"provenance": {
				"source": "payments/checkout.git",
				"commit": "9f31c0e",
			},
		},
		{
			"type": "upgrade",
			"recordedOn": "2026-10-15",
			"rollback": {
				"rehearsedOn": "2026-10-14",
			},
		},
	],
}

validate_input(record) := {
	"lifecycle": record,
	"today": today,
	"lifecycleFile": lifecycle_file,
}

gate_input(manifest, record) := {
	"lifecycle": record,
	"package": manifest,
	"today": today,
	"lifecycleFile": lifecycle_file,
	"packageFile": package_file,
}

control_input := gate_input(package_manifest, record_doc)

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

# Override the transitions wholesale.
with_transitions(record, transitions) := object.union(record, {"transitions": transitions})

# Override one field of one transition row, by transition type.
with_transition_field(record, kind, patch) := object.union(record, {"transitions": [transition_field_override(x, kind, patch) |
	some x in record.transitions
]})

transition_field_override(x, kind, patch) := replace_field(x, patch) if object.get(x, "type", null) == kind

transition_field_override(x, kind, patch) := x if object.get(x, "type", null) != kind

# Drop one transition row entirely, by transition type.
without_transition(record, kind) := object.union(record, {"transitions": [x |
	some x in record.transitions
	object.get(x, "type", null) != kind
]})

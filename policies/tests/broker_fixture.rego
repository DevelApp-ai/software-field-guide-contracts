# Shared fixture for the IAM-broker scope tests: one small, valid
# broker grant document after the issue #104 worked example — the
# platform team's broker declaring two consumer identities and
# issuing two grants, each vouching for a component the payments
# team's package manifest resolves: the storefront build pulling
# the customer-tier checkout package pinned at its published
# artifact digest, and the payments build pulling and attesting the
# platform baseline pinned as the package's dependency. Both
# expiries are in the future. The dates are chosen relative to the
# CI anchor date 2026-10-20.
package broker.fixture

import rego.v1

today := "2026-10-20"

broker_file := "grants.yaml"

package_file := "package.yaml"

package_manifest := {
	"component": "payments-checkout",
	"version": "1.4.0",
	"hierarchy": "customer",
	"reviewedOn": "2026-10-01",
	"owner": "Payments team",
	"artifactDigest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
	"dependencies": [
		{"package": "platform-baseline", "digest": "d6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44"},
	],
}

broker_doc := {
	"version": 1,
	"reviewedOn": "2026-10-18",
	"owner": "Platform team",
	"principals": ["storefront-build", "payments-build"],
	"grants": [
		{
			"principal": "storefront-build",
			"component": "payments-checkout",
			"digest": "5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c",
			"actions": ["pull"],
			"expires": "2026-12-31",
		},
		{
			"principal": "payments-build",
			"component": "platform-baseline",
			"digest": "d6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44",
			"actions": ["pull", "attest"],
			"expires": "2027-01-31",
		},
	],
}

# The gate reads both documents; the validator reads only the broker
# grant document and the clock.
gate_input(manifest, broker) := {
	"package": manifest,
	"broker": broker,
	"today": today,
	"packageFile": package_file,
	"brokerFile": broker_file,
}

validate_input(broker) := {
	"broker": broker,
	"today": today,
	"brokerFile": broker_file,
}

control_input := gate_input(package_manifest, broker_doc)

# --- override helpers -------------------------------------------------------
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

# Override one field of one grant row, by index.
with_grant_field(broker, index, patch) := object.union(broker, {"grants": [grant_field_override(g, i, index, patch) |
	some i, g in broker.grants
]})

grant_field_override(g, i, index, patch) := replace_field(g, patch) if i == index

grant_field_override(g, i, index, patch) := g if i != index

# Drop one grant row entirely, by index.
without_grant(broker, index) := object.union(broker, {"grants": [g |
	some i, g in broker.grants
	i != index
]})

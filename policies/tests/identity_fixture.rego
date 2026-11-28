# Shared fixture for the identity and secrets scope tests: one
# small, valid estate after the identity-and-secrets chapter's
# worked example — three declared identities on the payments
# platform, the secrets they reference, and the catalog that names
# each secret's kind, scope, rotation clock, and admitted
# consumers. One catalog secret is reserved (declared, rotation
# clocked, consumed by nobody): availability is not a drift. The
# dates are chosen relative to the CI anchor date 2026-10-20.
package identity.fixture

import rego.v1

today := "2026-10-20"

manifest_file := "manifest.yaml"

catalog_file := "catalog.yaml"

manifest := {
	"version": 3,
	"reviewedOn": "2026-10-18",
	"owner": "Platform security",
	"identities": [
		{
			"name": "checkout-web",
			"references": [
				{"secret": "payments-api-key", "scope": "payments:charges", "since": "2026-08-02"},
			],
		},
		{
			"name": "checkout-worker",
			"references": [
				{"secret": "payments-api-key", "scope": "payments:charges", "since": "2026-09-14"},
				{"secret": "settlement-signing-key", "scope": "settlements:sign", "since": "2026-08-20"},
			],
		},
		{
			"name": "billing-exporter",
			"references": [
				{"secret": "billing-read-token", "scope": "billing:read", "since": "2026-09-01"},
			],
		},
	],
}

catalog := {
	"version": 4,
	"reviewedOn": "2026-10-19",
	"owner": "Platform security",
	"secrets": [
		{
			"name": "payments-api-key",
			"kind": "api-key",
			"scope": "payments:charges",
			"rotatedOn": "2026-09-30",
			"maxAgeDays": 90,
			"consumers": ["checkout-web", "checkout-worker"],
		},
		{
			"name": "settlement-signing-key",
			"kind": "signing-key",
			"scope": "settlements:sign",
			"rotatedOn": "2026-10-01",
			"maxAgeDays": 60,
			"consumers": ["checkout-worker"],
		},
		{
			"name": "billing-read-token",
			"kind": "service-token",
			"scope": "billing:read",
			"rotatedOn": "2026-09-05",
			"maxAgeDays": 90,
			"consumers": ["billing-exporter"],
		},
		{
			"name": "reportstore-readonly",
			"kind": "service-token",
			"scope": "reportstore:read",
			"rotatedOn": "2026-10-02",
			"maxAgeDays": 180,
			"consumers": [],
		},
	],
}

validate_input(manifest_doc) := {
	"manifest": manifest_doc,
	"today": today,
	"manifestFile": manifest_file,
}

gate_input(manifest_doc, catalog_doc) := {
	"manifest": manifest_doc,
	"catalog": catalog_doc,
	"today": today,
	"manifestFile": manifest_file,
	"catalogFile": catalog_file,
}

control_input := gate_input(manifest, catalog)

# --- override helpers --------------------------------------------------------
#
# The #69 lesson, applied: an array comprehension with a condition
# in the body filters, so per-element overrides go through explicit
# two-definition helpers that always answer — the row itself when it
# does not match, the patched row when it does.

# Field replacement, not merge: object.union deep-merges object values,
# so a patch that means "this object is now X" removes the key first.
replace_field(obj, patch) := object.union(object.remove(obj, object.keys(patch)), patch)

# Override one top-level field of a document.
with_field(doc, patch) := replace_field(doc, patch)

# Override one top-level field of one identity row, by name.
with_identity_field(manifest_doc, name, patch) := object.union(manifest_doc, {"identities": [identity_field_override(i, name, patch) |
	some i in manifest_doc.identities
]})

identity_field_override(i, name, patch) := replace_field(i, patch) if object.get(i, "name", null) == name

identity_field_override(i, name, patch) := i if object.get(i, "name", null) != name

# Override one field of one reference row, addressed by its
# identity's name and the secret it references.
with_reference_field(manifest_doc, name, secret, patch) := object.union(manifest_doc, {"identities": [identity_reference_override(i, name, secret, patch) |
	some i in manifest_doc.identities
]})

identity_reference_override(i, name, secret, patch) := replace_field(i, {"references": [reference_override(r, secret, patch) |
	some r in i.references
]}) if object.get(i, "name", null) == name

identity_reference_override(i, name, secret, patch) := i if object.get(i, "name", null) != name

reference_override(r, secret, patch) := replace_field(r, patch) if object.get(r, "secret", null) == secret

reference_override(r, secret, patch) := r if object.get(r, "secret", null) != secret

# Override one field of one catalog secret row, by name.
with_secret_field(catalog_doc, name, patch) := object.union(catalog_doc, {"secrets": [secret_field_override(s, name, patch) |
	some s in catalog_doc.secrets
]})

secret_field_override(s, name, patch) := replace_field(s, patch) if object.get(s, "name", null) == name

secret_field_override(s, name, patch) := s if object.get(s, "name", null) != name

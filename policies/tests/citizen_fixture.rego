# Shared fixture for the citizen tests: one small, valid citizen
# estate after the citizen-development-on-spec-rails chapter's
# worked example — an expense-approver app a store-team citizen
# built on the platform's rails: two components whose behaviors the
# spec covers, two bindings riding the registry's one data rail,
# two actions the spec's rails grant, and two guardrails at the
# registry's platform floor. The dates are chosen relative to the
# CI anchor date 2026-10-20.
package citizen.fixture

import rego.v1

today := "2026-10-20"

manifest_file := "manifest.yaml"

spec_file := "spec.yaml"

registry_file := "guardrails.yaml"

manifest := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"owner": "Storefront team",
	"app": "expense-approver",
	"components": [
		{"name": "claim-form", "behavior": "submits an expense claim"},
		{"name": "claim-rules", "behavior": "approves a claim inside its policy"},
	],
	"dataBindings": [
		{"name": "claims-store", "mode": "read", "via": "platform-data-api"},
		{"name": "audit-log", "mode": "write", "via": "platform-data-api"},
	],
	"actions": ["expense.submit", "expense.approve"],
	"guardrails": [
		{"name": "data-guardrail", "version": 3},
		{"name": "action-guardrail", "version": 2},
	],
}

spec := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"owner": "Storefront team",
	"actions": ["expense.submit", "expense.approve"],
	"coverage": ["submits an expense claim", "approves a claim inside its policy"],
}

registry := {
	"version": 1,
	"reviewedOn": "2026-10-15",
	"owner": "Platform team",
	"dataRails": ["platform-data-api"],
	"platformFloor": [
		{"name": "data-guardrail", "floor": 3},
		{"name": "action-guardrail", "floor": 2},
	],
}

validate_input(manifest_doc) := {
	"manifest": manifest_doc,
	"today": today,
	"manifestFile": manifest_file,
}

gate_input(manifest_doc, spec_doc, registry_doc) := {
	"manifest": manifest_doc,
	"spec": spec_doc,
	"registry": registry_doc,
	"today": today,
	"manifestFile": manifest_file,
	"specFile": spec_file,
	"registryFile": registry_file,
}

control_input := gate_input(manifest, spec, registry)

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

# Override one field of one component row, by name.
with_component_field(manifest_doc, name, patch) := object.union(manifest_doc, {"components": [component_field_override(c, name, patch) |
	some c in manifest_doc.components
]})

component_field_override(c, name, patch) := replace_field(c, patch) if object.get(c, "name", null) == name

component_field_override(c, name, patch) := c if object.get(c, "name", null) != name

# Override one field of one data-binding row, by name.
with_binding_field(manifest_doc, name, patch) := object.union(manifest_doc, {"dataBindings": [binding_field_override(b, name, patch) |
	some b in manifest_doc.dataBindings
]})

binding_field_override(b, name, patch) := replace_field(b, patch) if object.get(b, "name", null) == name

binding_field_override(b, name, patch) := b if object.get(b, "name", null) != name

# Override one field of one guardrail row, by name.
with_guardrail_field(manifest_doc, name, patch) := object.union(manifest_doc, {"guardrails": [guardrail_field_override(g, name, patch) |
	some g in manifest_doc.guardrails
]})

guardrail_field_override(g, name, patch) := replace_field(g, patch) if object.get(g, "name", null) == name

guardrail_field_override(g, name, patch) := g if object.get(g, "name", null) != name

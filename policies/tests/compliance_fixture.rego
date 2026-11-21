# Shared fixture for the compliance tests: one small, valid pair of
# documents after the compliance-as-code chapter's worked example —
# the storefront's requirements catalog (a PCI DSS pair, a SOC 2
# obligation, and the GDPR erasure window) and the platform team's
# controls manifest, one control per requirement, each citing one
# live, named evidence source and carrying a fresh review clock. The
# review dates are chosen relative to the CI anchor date 2026-10-20.
package compliance.fixture

import rego.v1

today := "2026-10-20"

controls_file := "controls.yaml"

requirements_file := "requirements.yaml"

requirements_catalog := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"owner": "Compliance team",
	"requirements": [
		{"id": "PCI-DSS-2.2.7", "title": "Firewall and router rule sets are reviewed and re-approved at least every six months", "source": "PCI DSS v4.0"},
		{"id": "PCI-DSS-3.4.1", "title": "Cardholder data is rendered unreadable wherever it is stored", "source": "PCI DSS v4.0"},
		{"id": "SOC2-CC6.1", "title": "Logical access to infrastructure is restricted to authorized users", "source": "SOC 2 Type II, CC6.1"},
		{"id": "GDPR-ART-17", "title": "Personal data is erased within thirty days of a verified erasure request", "source": "GDPR art. 17"},
	],
}

controls_manifest := {
	"version": 1,
	"reviewedOn": "2026-10-18",
	"owner": "Platform team",
	"evidenceSources": [
		{"id": "edge-firewall-review", "kind": "review record", "status": "live"},
		{"id": "encryption-config-scan", "kind": "scanner output", "status": "live"},
		{"id": "edge-access-logs", "kind": "log store", "status": "live"},
		{"id": "erasure-case-registry", "kind": "case registry", "status": "live"},
	],
	"controls": [
		{
			"id": "CTRL-01",
			"title": "Edge firewall rule set reviewed and re-approved quarterly",
			"owner": "Platform team",
			"requirements": ["PCI-DSS-2.2.7"],
			"evidenceSource": "edge-firewall-review",
			"reviewedOn": "2026-09-15",
			"intervalDays": 180,
		},
		{
			"id": "CTRL-02",
			"title": "Data-at-rest encryption verified by the nightly config scan",
			"owner": "Storefront team",
			"requirements": ["PCI-DSS-3.4.1"],
			"evidenceSource": "encryption-config-scan",
			"reviewedOn": "2026-10-10",
			"intervalDays": 90,
		},
		{
			"id": "CTRL-03",
			"title": "Edge access restricted to authenticated identities",
			"owner": "Platform team",
			"requirements": ["SOC2-CC6.1"],
			"evidenceSource": "edge-access-logs",
			"reviewedOn": "2026-10-05",
			"intervalDays": 90,
		},
		{
			"id": "CTRL-04",
			"title": "Erasure cases closed inside the thirty-day window",
			"owner": "Platform team",
			"requirements": ["GDPR-ART-17"],
			"evidenceSource": "erasure-case-registry",
			"reviewedOn": "2026-07-01",
			"intervalDays": 180,
		},
	],
}

validate_input(controls_doc) := {
	"controls": controls_doc,
	"today": today,
	"controlsFile": controls_file,
}

gate_input(controls_doc, requirements_doc) := {
	"controls": controls_doc,
	"requirements": requirements_doc,
	"today": today,
	"controlsFile": controls_file,
	"requirementsFile": requirements_file,
}

control_input := gate_input(controls_manifest, requirements_catalog)

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

# Override one field of one control row, by id.
with_control_field(manifest, id, patch) := object.union(manifest, {"controls": [control_field_override(c, id, patch) |
	some c in manifest.controls
]})

control_field_override(c, id, patch) := replace_field(c, patch) if object.get(c, "id", null) == id

control_field_override(c, id, patch) := c if object.get(c, "id", null) != id

# Drop one control row entirely, by id.
without_control(manifest, id) := object.union(manifest, {"controls": [c |
	some c in manifest.controls
	object.get(c, "id", null) != id
]})

# Override one field of one evidence source row, by id.
with_source_field(manifest, id, patch) := object.union(manifest, {"evidenceSources": [source_field_override(s, id, patch) |
	some s in manifest.evidenceSources
]})

source_field_override(s, id, patch) := replace_field(s, patch) if object.get(s, "id", null) == id

source_field_override(s, id, patch) := s if object.get(s, "id", null) != id

# Drop one evidence source row entirely, by id.
without_source(manifest, id) := object.union(manifest, {"evidenceSources": [s |
	some s in manifest.evidenceSources
	object.get(s, "id", null) != id
]})

# Override one field of one catalog requirement row, by id.
with_requirement_field(catalog, id, patch) := object.union(catalog, {"requirements": [requirement_field_override(x, id, patch) |
	some x in catalog.requirements
]})

requirement_field_override(x, id, patch) := replace_field(x, patch) if object.get(x, "id", null) == id

requirement_field_override(x, id, patch) := x if object.get(x, "id", null) != id

# Drop one catalog requirement row entirely, by id.
without_requirement(catalog, id) := object.union(catalog, {"requirements": [x |
	some x in catalog.requirements
	object.get(x, "id", null) != id
]})

# Add one catalog requirement row — the seeded unmapped obligation.
with_requirement(catalog, row) := object.union(catalog, {"requirements": array.concat(catalog.requirements, [row])})

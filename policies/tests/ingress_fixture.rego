# Shared fixture for the ingress tests: one small, valid edge
# estate after the secure-developer-ingress chapter's worked example
# — a platform zoned dev.internal, one contained wildcard and one
# concrete partner host, two certificates outside their rotation
# windows, one SLO with its pager, three route classes all logged,
# and the seal-edge kill path rehearsed ten days before the anchor
# date on a well-formed drill record. The dates are chosen relative
# to the CI anchor date 2026-10-20.
package ingress.fixture

import rego.v1

today := "2026-10-20"

case_file := "ingress-case.yaml"

drill_file := "drill.yaml"

case := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"owner": "Platform team",
	"zone": "dev.internal",
	"requestPolicy": {
		"defaultDeny": true,
		"decision": "deny every request the allowed domains do not admit",
	},
	"domains": [
		{"pattern": "*.dev.internal", "intent": "every developer app tenant, inside the platform zone"},
		{"pattern": "partner.example.com", "intent": "the one external partner host the storefront fronts"},
	],
	"certs": [
		{"serves": "edge.dev.internal", "notBefore": "2026-08-01", "notAfter": "2027-01-15", "rotateByDays": 30},
		{"serves": "partner.example.com", "notBefore": "2026-07-01", "notAfter": "2026-12-15", "rotateByDays": 21},
	],
	"slos": [{"name": "edge availability", "target": "99.9% of requests served inside 200ms", "pager": "platform on-call"}],
	"routes": [
		{"class": "developer-app"},
		{"class": "partner-api"},
		{"class": "health-check"},
	],
	"loggedRouteClasses": ["developer-app", "partner-api", "health-check"],
	"killPath": {
		"name": "seal-edge",
		"effect": "the edge denies all ingress and the platform seals inside its zone",
	},
}

drill := {
	"version": 1,
	"reviewedOn": "2026-10-15",
	"owner": "Platform team",
	"maxStalenessDays": 180,
	"drills": [{"killPath": "seal-edge", "drilledOn": "2026-10-10", "evidence": "drill log 2026-10-10: seal-edge pulled, all ingress denied for 90 seconds, recovery clean"}],
}

validate_input(case_doc) := {
	"case": case_doc,
	"today": today,
	"caseFile": case_file,
}

gate_input(case_doc, drill_doc) := {
	"case": case_doc,
	"drill": drill_doc,
	"today": today,
	"caseFile": case_file,
	"drillFile": drill_file,
}

control_input := gate_input(case, drill)

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

# Override one field of one domain row, by pattern.
with_domain_field(case_doc, pattern, patch) := object.union(case_doc, {"domains": [domain_field_override(d, pattern, patch) |
	some d in case_doc.domains
]})

domain_field_override(d, pattern, patch) := replace_field(d, patch) if object.get(d, "pattern", null) == pattern

domain_field_override(d, pattern, patch) := d if object.get(d, "pattern", null) != pattern

# Override one field of one certificate row, by the host it serves.
with_cert_field(case_doc, serves, patch) := object.union(case_doc, {"certs": [cert_field_override(c, serves, patch) |
	some c in case_doc.certs
]})

cert_field_override(c, serves, patch) := replace_field(c, patch) if object.get(c, "serves", null) == serves

cert_field_override(c, serves, patch) := c if object.get(c, "serves", null) != serves

# Override one field of one SLO row, by name.
with_slo_field(case_doc, name, patch) := object.union(case_doc, {"slos": [slo_field_override(s, name, patch) |
	some s in case_doc.slos
]})

slo_field_override(s, name, patch) := replace_field(s, patch) if object.get(s, "name", null) == name

slo_field_override(s, name, patch) := s if object.get(s, "name", null) != name

# Override one field of one drill-rehearsal row, by the kill path it
# names.
with_drill_row_field(drill_doc, kill_path, patch) := object.union(drill_doc, {"drills": [drill_row_override(d, kill_path, patch) |
	some d in drill_doc.drills
]})

drill_row_override(d, kill_path, patch) := replace_field(d, patch) if object.get(d, "killPath", null) == kill_path

drill_row_override(d, kill_path, patch) := d if object.get(d, "killPath", null) != kill_path

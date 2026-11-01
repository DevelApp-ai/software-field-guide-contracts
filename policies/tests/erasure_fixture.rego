# Shared fixture for the erasure tests: one small, valid DEK registry
# and two erasure cases in the storefront flavor of the book's
# examples — three tenants (two destroyed with their evidence records,
# one live), a storage inventory with a primary, a replica, a derived
# index, and a backup that resolves by expiry, and sweep records for
# every sweepable store.
#
# The review dates are chosen relative to the CI anchor date
# 2026-10-20.
package erasure.fixture

import rego.v1

today := "2026-10-20"

keys := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"keys": [
		{
			"dek": "tenant-acme-dek-004",
			"tenant": "tenant-acme",
			"state": "destroyed",
			"destroyedAt": "2026-10-02",
			"destroyedBy": "KMS DestroyKey in change CHG-4471; key material unrecoverable, cf. runbook RB-014",
		},
		{
			"dek": "tenant-globex-dek-002",
			"tenant": "tenant-globex",
			"state": "destroyed",
			"destroyedAt": "2026-10-06",
			"destroyedBy": "KMS DestroyKey in change CHG-4488; key material unrecoverable, cf. runbook RB-014",
		},
		{
			"dek": "tenant-initech-dek-001",
			"tenant": "tenant-initech",
			"state": "active",
		},
	],
}

# The destroyed-DEK control: every store swept or aged out, the
# backup's expiry window passed, the case closed — the verdict the
# gate owes the tenant: forgotten.
case_forgotten := {
	"owner": "Platform team",
	"reviewedOn": "2026-10-19",
	"tenant": "tenant-acme",
	"requestedOn": "2026-10-01",
	"requestedBy": "DSR-2026-041 (tenant offboarding erasure request)",
	"status": "closed",
	"stores": [
		{"name": "postgres-primary", "kind": "primary"},
		{"name": "postgres-replica-eu", "kind": "replica"},
		{"name": "corpus-vector-index", "kind": "vector-store"},
		{"name": "nightly-backups", "kind": "backup", "expiresOn": "2026-10-15"},
	],
	"sweeps": [
		{
			"store": "postgres-primary",
			"sweptOn": "2026-10-02",
			"sweptBy": "DELETE cascade from the tenant row; 412 rows removed, count verified by the tenant-id scan",
		},
		{
			"store": "postgres-replica-eu",
			"sweptOn": "2026-10-03",
			"sweptBy": "replica catch-up confirmed; the tenant-id scan returns zero rows on the replica",
		},
		{
			"store": "corpus-vector-index",
			"sweptOn": "2026-10-04",
			"sweptBy": "index rebuild without the tenant's corpus; embedding count verified",
		},
	],
}

# The unexpired backup: the sweep records cover the primaries and the
# index, the DEK is destroyed — but the nightly backup ages out on
# 2027-01-15, still in the future. The case stays open, honestly: the
# verdict is pending, not forgotten.
case_pending := {
	"owner": "Platform team",
	"reviewedOn": "2026-10-19",
	"tenant": "tenant-globex",
	"requestedOn": "2026-10-05",
	"requestedBy": "DSR-2026-052 (tenant offboarding erasure request)",
	"status": "open",
	"stores": [
		{"name": "postgres-primary", "kind": "primary"},
		{"name": "corpus-vector-index", "kind": "vector-store"},
		{"name": "nightly-backups", "kind": "backup", "expiresOn": "2027-01-15"},
	],
	"sweeps": [
		{
			"store": "postgres-primary",
			"sweptOn": "2026-10-06",
			"sweptBy": "DELETE cascade from the tenant row; 208 rows removed, count verified by the tenant-id scan",
		},
		{
			"store": "corpus-vector-index",
			"sweptOn": "2026-10-06",
			"sweptBy": "index rebuild without the tenant's corpus; embedding count verified",
		},
	],
}

validate_input(keys_doc) := {
	"keys": keys_doc,
	"today": today,
}

gate_input(keys_doc, case_doc) := {
	"keys": keys_doc,
	"case": case_doc,
	"today": today,
}

# --- registry override helpers ----------------------------------------------
#
# The #69 lesson, applied: an array comprehension with a condition in
# the body filters, so per-element overrides go through explicit
# two-definition helpers that always answer — the row itself when it
# does not match, the patched row when it does.

# Field replacement, not merge: object.union deep-merges object values,
# so a patch that means "this object is now X" removes the key first.
replace_field(obj, patch) := object.union(object.remove(obj, object.keys(patch)), patch)

# Override one field of one registry row, by dek.
with_key_field(keys_doc, dek, patch) := object.union(keys_doc, {"keys": [key_field_override(k, dek, patch) |
	some k in keys_doc.keys
]})

key_field_override(k, dek, patch) := replace_field(k, patch) if object.get(k, "dek", null) == dek

key_field_override(k, dek, patch) := k if object.get(k, "dek", null) != dek

# Remove one field from one registry row, by dek.
without_key_field(keys_doc, dek, field) := object.union(keys_doc, {"keys": [key_field_removal(k, dek, field) |
	some k in keys_doc.keys
]})

key_field_removal(k, dek, field) := object.remove(k, {field}) if object.get(k, "dek", null) == dek

key_field_removal(k, dek, field) := k if object.get(k, "dek", null) != dek

# --- case override helpers -----------------------------------------------------

# Override one top-level field of the case.
with_case_field(case_doc, patch) := replace_field(case_doc, patch)

# Drop the sweep record covering one store — the seeded gap in the
# trail: the store stays in the inventory, the record vanishes.
without_sweep(case_doc, store) := object.union(case_doc, {"sweeps": [w |
	some w in case_doc.sweeps
	w.store != store
]})

# Add one sweep record to the case.
with_sweep(case_doc, sweep) := object.union(case_doc, {"sweeps": array.concat(case_doc.sweeps, [sweep])})

# Override one field of one inventory store, by name.
with_store_field(case_doc, name, patch) := object.union(case_doc, {"stores": [store_field_override(s, name, patch) |
	some s in case_doc.stores
]})

store_field_override(s, name, patch) := replace_field(s, patch) if object.get(s, "name", null) == name

store_field_override(s, name, patch) := s if object.get(s, "name", null) != name

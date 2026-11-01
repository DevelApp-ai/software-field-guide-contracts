package erasure.gate_test

import rego.v1

import data.erasure

import data.erasure.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_control_case_passes_and_renders_forgotten if {
	r := erasure.gate with input as fixture.gate_input(fixture.keys, fixture.case_forgotten)
	r.valid == true
	count(r.findings) == 0
	r.verdict == "forgotten"
	count(r.stores) == 4

	# one card per inventory store, sorted by store name
	r.stores[0].store == "corpus-vector-index"
	r.stores[0].verdict == "swept"
	r.stores[0].detail == "swept on 2026-10-04"
	r.stores[1].store == "nightly-backups"
	r.stores[1].verdict == "expired"
	r.stores[1].detail == "backup aged out on 2026-10-15"
	r.stores[2].store == "postgres-primary"
	r.stores[2].verdict == "swept"
	r.stores[3].store == "postgres-replica-eu"
	r.stores[3].verdict == "swept"
}

# The issue's done-when: an unexpired backup renders pending, honest
# and the case stays open until the window closes.
test_unexpired_backup_renders_pending_honest if {
	r := erasure.gate with input as fixture.gate_input(fixture.keys, fixture.case_pending)
	r.valid == true
	r.verdict == "pending, honest"
	backup := [s | some s in r.stores; s.store == "nightly-backups"][0]
	backup.verdict == "pending"
	backup.detail == "backup window open until 2027-01-15"
}

test_input_must_be_object if {
	r := erasure.gate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_missing_keys if {
	r := erasure.gate with input as {"case": fixture.case_forgotten, "today": fixture.today}
	not r.valid
	error_rules(r)["keys/missing"]
}

test_missing_case if {
	r := erasure.gate with input as {"keys": fixture.keys, "today": fixture.today}
	not r.valid
	error_rules(r)["case/missing"]
}

# --- the case's own stamps ---------------------------------------------------

test_owner_required if {
	c := object.remove(fixture.case_forgotten, ["owner"])
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/owner-required"]
}

test_reviewed_on_invalid if {
	c := object.union(fixture.case_forgotten, {"reviewedOn": "not-a-date"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	c := object.union(fixture.case_forgotten, {"reviewedOn": "2026-10-21"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/reviewed-in-future"]
}

test_reviewed_stale if {
	c := object.union(fixture.case_forgotten, {"reviewedOn": "2025-10-19"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/reviewed-stale"]
}

# --- the case must be readable --------------------------------------------------

test_tenant_required if {
	c := object.remove(fixture.case_forgotten, ["tenant"])
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/tenant-required"]
}

test_requested_on_invalid if {
	c := object.union(fixture.case_forgotten, {"requestedOn": "October"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/requested-on-invalid"]
}

test_requested_in_future if {
	c := object.union(fixture.case_forgotten, {"requestedOn": "2026-10-21"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/requested-in-future"]
}

test_requested_by_required if {
	c := object.remove(fixture.case_forgotten, ["requestedBy"])
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/requested-by-required"]
}

test_status_unknown if {
	c := object.union(fixture.case_forgotten, {"status": "mostly done"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/status-unknown"]
}

# --- the storage inventory --------------------------------------------------------

test_stores_must_be_array if {
	c := object.remove(fixture.case_forgotten, ["stores"])
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["stores/must-be-array"]
}

# The issue's own words: an incomplete inventory is a finding.
test_empty_inventory_is_a_finding if {
	c := object.union(fixture.case_forgotten, {"stores": []})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	some f in r.findings
	f.rule == "stores/required"
	contains(f.message, "an empty inventory claims the data is nowhere")
}

test_store_name_required if {
	c := object.union(fixture.case_forgotten, {"stores": [
		{"name": "", "kind": "primary"},
		fixture.case_forgotten.stores[1],
		fixture.case_forgotten.stores[2],
		fixture.case_forgotten.stores[3],
	]})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	some f in r.findings
	f.rule == "store/name-required"
	f.path == "$.case.stores[0].name"
}

test_store_kind_required if {
	c := fixture.with_store_field(fixture.case_forgotten, "postgres-primary", {"kind": ""})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["store/kind-required"]
}

test_store_name_duplicate if {
	c := object.union(fixture.case_forgotten, {"stores": array.concat(fixture.case_forgotten.stores, [{"name": "postgres-primary", "kind": "replica"}])})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["store/name-duplicate"]
}

test_backup_expiry_required if {
	# a swept backup without its declared window never becomes
	# provably gone — the sweep is not the point, the window is
	c := fixture.with_sweep(fixture.with_store_field(fixture.case_forgotten, "nightly-backups", {"expiresOn": null}), {
		"store": "nightly-backups",
		"sweptOn": "2026-10-02",
		"sweptBy": "backup rotation pruned the tenant's rows",
	})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	some f in r.findings
	f.rule == "store/backup-expiry-required"
	f.path == "$.case.stores[3].expiresOn"
	contains(f.message, "a backup without its expiry window never becomes provably gone")
}

# --- the sweep records ---------------------------------------------------------------

test_sweeps_must_be_array if {
	c := object.remove(fixture.case_forgotten, ["sweeps"])
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["sweeps/must-be-array"]
}

test_sweep_row_invalid if {
	c := object.union(fixture.case_forgotten, {"sweeps": array.concat(fixture.case_forgotten.sweeps, [{"store": "postgres-primary", "sweptOn": "2026-10-03"}])})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["sweep/row-invalid"]
}

test_sweep_for_an_undeclared_store_is_caught if {
	c := fixture.with_sweep(fixture.case_forgotten, {
		"store": "ghost-store",
		"sweptOn": "2026-10-03",
		"sweptBy": "nobody knows what this swept",
	})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	some f in r.findings
	f.rule == "sweep/store-unknown"
	contains(f.message, "the two documents disagree")
}

test_sweep_before_request_is_caught if {
	c := fixture.with_sweep(fixture.case_forgotten, {
		"store": "postgres-primary",
		"sweptOn": "2026-09-28",
		"sweptBy": "a routine purge that predates the case",
	})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	some f in r.findings
	f.rule == "sweep/before-request"
	contains(f.message, "before the erasure request arrived on 2026-10-01")
}

test_sweep_in_future_is_caught if {
	c := fixture.with_sweep(fixture.case_forgotten, {
		"store": "postgres-primary",
		"sweptOn": "2026-10-21",
		"sweptBy": "a sweep that has not happened yet",
	})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["sweep/in-future"]
}

# --- the issue's core rule: nothing is forgotten without a record ----------------

test_replica_without_its_sweep_record_is_caught_citing_the_store if {
	c := fixture.without_sweep(fixture.case_forgotten, "postgres-replica-eu")
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	r.verdict == "incomplete"

	# it bites exactly once, and it names the store
	count([f | some f in r.findings; f.rule == "sweep/store-unswept"]) == 1
	some f in r.findings
	f.rule == "sweep/store-unswept"
	f.path == "$.case.stores[1]"
	contains(f.message, "postgres-replica-eu")
	contains(f.message, "nothing is forgotten without a record")

	# and the card renders the store as unswept
	replica := [s | some s in r.stores; s.store == "postgres-replica-eu"][0]
	replica.verdict == "unswept"
	replica.detail == "no sweep record and no pending reason"
}

# --- the case must lean on the registry --------------------------------------------

test_tenant_unregistered_is_caught if {
	c := fixture.with_case_field(fixture.case_forgotten, {"tenant": "tenant-hooli"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	some f in r.findings
	f.rule == "keys/tenant-unregistered"
	contains(f.message, "tenant-hooli")
}

test_live_dek_is_caught_citing_the_key if {
	c := fixture.with_case_field(fixture.case_forgotten, {"tenant": "tenant-initech", "status": "open"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	some f in r.findings
	f.rule == "keys/dek-not-destroyed"
	f.path == "$.keys.keys[2]"
	contains(f.message, "tenant-initech-dek-001")
	contains(f.message, "with the key alive the ciphertext is readable")
}

# --- the case's own status, judged against its evidence ------------------------------

test_case_closed_while_backup_window_open_is_caught if {
	c := fixture.with_case_field(fixture.case_pending, {"status": "closed"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	some f in r.findings
	f.rule == "case/closed-early"
	f.path == "$.case.status"
	contains(f.message, "nightly-backups")
	contains(f.message, "backup window open until 2027-01-15")
}

test_closable_case_warns_but_stays_valid if {
	# the control evidence with the status flipped back to open: the
	# case can close honestly — a warning, never an error
	c := fixture.with_case_field(fixture.case_forgotten, {"status": "open"})
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	r.valid == true
	r.verdict == "forgotten"
	some f in r.findings
	f.severity == "warning"
	f.rule == "case/closable"
}

# --- the pending reason: a promise with words in it --------------------------------

test_pending_reason_resolves_a_store if {
	# a reindex cycle is a promise with a date attached to nobody —
	# the case declares the reason and stays honest, open
	c := fixture.with_store_field(
		fixture.without_sweep(fixture.with_case_field(fixture.case_forgotten, {"status": "open"}), "corpus-vector-index"),
		"corpus-vector-index",
		{"pendingReason": "reindex cycle queued for week 44"},
	)
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	r.valid == true
	r.verdict == "pending, honest"
	index := [s | some s in r.stores; s.store == "corpus-vector-index"][0]
	index.verdict == "pending"
	index.detail == "reindex cycle queued for week 44"
}

test_pending_reason_does_not_permit_closing if {
	# the same reason, the status closed: a pending store is a store
	# that can still produce the data — the reason is a promise, not
	# an erasure
	c := fixture.with_store_field(
		fixture.without_sweep(fixture.case_forgotten, "corpus-vector-index"),
		"corpus-vector-index",
		{"pendingReason": "reindex cycle queued for week 44"},
	)
	r := erasure.gate with input as fixture.gate_input(fixture.keys, c)
	not r.valid
	error_rules(r)["case/closed-early"]
}

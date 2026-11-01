# The shared model for the deletion evidence gate — The Software Field
# Guide, issue #79.
#
# Two documents enter: the DEK registry (the per-tenant data-encryption-key
# rows, each with its state and, when destroyed, the day it died and what
# destroyed it) and the erasure case (the per-tenant right-to-be-forgotten
# record: the request that opened it, the storage inventory, the sweep
# records, and the backup windows still open). The registry is the
# strongest verified deletion primitive the book has; the case is the
# evidence that every other copy followed it into the dark. Every
# accessor here guards its input before touching object fields — a
# malformed document must produce findings, never a WASM trap.
package erasure

import rego.v1

import data.erasure.lib

# --- the input documents ------------------------------------------------------

keys_doc := v if {
	is_object(input)
	v := object.get(input, "keys", null)
}

keys_doc := null if not is_object(input)

case_doc := v if {
	is_object(input)
	v := object.get(input, "case", null)
}

case_doc := null if not is_object(input)

# The injected clock, guarded: `today` arrives with the input and is
# never read from the wall. Accessed through this accessor so a
# malformed input (an array, a string) can never trap a builtin.
today_date := v if {
	is_object(input)
	v := object.get(input, "today", null)
}

today_date := null if not is_object(input)

# --- arrays, defensively ------------------------------------------------------

# A named array field of a document, or [] when the field is absent,
# malformed, or the document itself is not an object.
as_array(doc, key) := arr if {
	is_object(doc)
	arr := object.get(doc, key, [])
	is_array(arr)
}

as_array(doc, key) := [] if {
	is_object(doc)
	not is_array(object.get(doc, key, []))
}

as_array(doc, key) := [] if not is_object(doc)

# --- the DEK registry: key rows ----------------------------------------------

key_rows := [k | some k in as_array(keys_doc, "keys"); is_object(k)]

key_dek(k) := object.get(k, "dek", null)

key_tenant(k) := object.get(k, "tenant", null)

key_state(k) := object.get(k, "state", null)

key_destroyed_at(k) := object.get(k, "destroyedAt", null)

key_destroyed_by(k) := object.get(k, "destroyedBy", null)

# A registry row a lookup can trust: named key, named tenant. Shape
# quality beyond this is the validator's finding, never an ambiguity
# for lookups.
key_row_well_formed(k) if {
	is_object(k)
	lib.is_nonempty_string(key_dek(k))
	lib.is_nonempty_string(key_tenant(k))
}

# The position of a row in the registry document, so a finding can
# cite the exact row.
key_index(dek) := i if {
	matches := [i |
		some i, k in key_rows
		key_row_well_formed(k)
		object.get(k, "dek", null) == dek
	]
	count(matches) > 0
	i := matches[0]
}

# --- the DEK registry: the tenant join ----------------------------------------

# The well-formed registry rows for one tenant — the crypto-erasure
# side of the join. A tenant with no row is unregistered; a tenant
# with any live row is not erased.
tenant_keys(tenant) := [k |
	some k in key_rows
	key_row_well_formed(k)
	key_tenant(k) == tenant
]

tenant_registered(tenant) if {
	count(tenant_keys(tenant)) > 0
}

tenant_deks_destroyed(tenant) if {
	count(tenant_keys(tenant)) > 0
	every k in tenant_keys(tenant) {
		key_state(k) == "destroyed"
	}
}

# The first live key for a tenant (in document order) — the one a
# finding cites when the erasure still has a working key.
first_live_key(tenant) := k if {
	matches := [k |
		some k in tenant_keys(tenant)
		key_state(k) != "destroyed"
	]
	count(matches) > 0
	k := matches[0]
}

# --- the erasure case: the record fields ------------------------------------------

case_tenant := v if {
	is_object(case_doc)
	v := object.get(case_doc, "tenant", null)
}

case_tenant := null if not is_object(case_doc)

case_requested_on := v if {
	is_object(case_doc)
	v := object.get(case_doc, "requestedOn", null)
}

case_requested_on := null if not is_object(case_doc)

case_status := v if {
	is_object(case_doc)
	v := object.get(case_doc, "status", null)
}

case_status := null if not is_object(case_doc)

# --- the erasure case: the storage inventory ----------------------------------------

stores := [s | some s in as_array(case_doc, "stores"); is_object(s)]

store_name(s) := object.get(s, "name", null)

store_kind(s) := object.get(s, "kind", null)

store_expires_on(s) := object.get(s, "expiresOn", null)

store_pending_reason(s) := object.get(s, "pendingReason", null)

store_row_well_formed(s) if {
	is_object(s)
	lib.is_nonempty_string(store_name(s))
	lib.is_nonempty_string(store_kind(s))
}

# The position of a store in the case document, so a finding can cite
# the exact row.
store_index(name) := i if {
	matches := [i |
		some i, s in stores
		store_row_well_formed(s)
		object.get(s, "name", null) == name
	]
	count(matches) > 0
	i := matches[0]
}

store_names := {store_name(s) |
	some s in stores
	store_row_well_formed(s)
}

store_is_backup(s) if {
	store_row_well_formed(s)
	store_kind(s) == "backup"
}

# --- the erasure case: the sweep records ---------------------------------------------

sweeps := [w | some w in as_array(case_doc, "sweeps"); is_object(w)]

sweep_store(w) := object.get(w, "store", null)

sweep_on(w) := object.get(w, "sweptOn", null)

sweep_by(w) := object.get(w, "sweptBy", null)

# A sweep record a gate can trust: the store named, the day real, and
# the hand that swept named — nothing is forgotten without a record,
# and a record names its actor.
sweep_row_well_formed(w) if {
	is_object(w)
	lib.is_nonempty_string(sweep_store(w))
	lib.is_valid_date(sweep_on(w))
	lib.is_nonempty_string(sweep_by(w))
}

# The well-formed sweep records covering one store, in document order.
sweeps_for(name) := [w |
	some w in sweeps
	sweep_row_well_formed(w)
	sweep_store(w) == name
]

store_swept(s) if {
	count(sweeps_for(store_name(s))) > 0
}

# --- store resolution: swept, aged out, or honestly pending -------------------------

# A backup resolves by expiry as honestly as by sweeping: when the
# retention window has passed, the bytes are gone and the expiry date
# is the record. Until then the window is the pending state — an
# unexpired backup is honest, not a failure.
backup_expired(s) if {
	store_is_backup(s)
	lib.is_valid_date(store_expires_on(s))
	lib.is_valid_date(today_date)
	lib.date_to_days(store_expires_on(s)) <= lib.date_to_days(today_date)
}

backup_window_open(s) if {
	store_is_backup(s)
	lib.is_valid_date(store_expires_on(s))
	lib.is_valid_date(today_date)
	lib.date_to_days(store_expires_on(s)) > lib.date_to_days(today_date)
}

# A store may declare an explicit pending reason instead: a reindex
# cycle, a provider queue, a window the case is waiting out. A reason
# is a promise with words in it; without one, an unswept store is a
# gate failure.
store_pending_by_reason(s) if {
	store_row_well_formed(s)
	lib.is_nonempty_string(store_pending_reason(s))
}

store_pending(s) if backup_window_open(s)

store_pending(s) if store_pending_by_reason(s)

store_resolved(s) if store_swept(s)

store_resolved(s) if backup_expired(s)

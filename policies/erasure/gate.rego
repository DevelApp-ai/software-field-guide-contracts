# Erasure case gate — The Software Field Guide, issue #79.
#
# The #69 rule, moved from alerting to erasure: nothing is forgotten
# without a record. The gate reads the erasure case — the per-tenant
# right-to-be-forgotten evidence: the request that opened it, the
# storage inventory, the sweep records, and the backup windows still
# open — against the DEK registry, and fails loudly when the paper
# trail is broken: a store in the inventory that no sweep record
# covers and no pending reason explains (sweep/store-unswept), a
# backup without its expiry window (store/backup-expiry-required), a
# sweep dated before the request that opened the case
# (sweep/before-request), a tenant whose keys the registry still
# holds live (keys/dek-not-destroyed), and a case that claims closed
# while a store can still produce the data (case/closed-early). An
# unexpired backup is an honest pending state, not a failure — the
# case stays open until the window closes. The stores list renders
# the decision: each store in the inventory, swept, aged out, pending,
# or unswept.
#
# Input (JSON): {"keys": {...}, "case": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [...], "stores": [...], "verdict": "..."}
package erasure

import rego.v1

import data.erasure.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"stores": store_cards,
		"verdict": case_verdict(fs),
	}
}

gate_findings := (((((((((((((f_input_invalid | f_today_invalid) | f_keys_missing) | f_case_missing) | f_case_stamps) | f_case_content) | f_stores_array) | f_stores_content) | f_backup_expiry) | f_sweeps_array) | f_sweeps_content) | f_sweep_refs) | f_gate_stores) | f_gate_keys) | f_gate_case

# --- findings: the case's own stamps --------------------------------------------

# The case is evidence, and evidence has a shelf life: a case nobody
# re-reads is a case whose evidence nobody still believes.
f_case_stamps contains finding if {
	is_object(case_doc)
	not lib.is_nonempty_string(object.get(case_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "case/owner-required",
		"message": "the erasure case must name an owner: a deletion case with an owner and a review cadence is the discipline",
		"path": "$.case.owner",
	}
}

f_case_stamps contains finding if {
	is_object(case_doc)
	not lib.is_valid_date(object.get(case_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "case/reviewed-on-invalid",
		"message": "the erasure case must carry reviewedOn as a real YYYY-MM-DD date",
		"path": "$.case.reviewedOn",
	}
}

f_case_stamps contains finding if {
	is_object(case_doc)
	lib.is_valid_date(object.get(case_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(case_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "case/reviewed-in-future",
		"message": "the erasure case carries a reviewedOn date in the future",
		"path": "$.case.reviewedOn",
	}
}

f_case_stamps contains finding if {
	is_object(case_doc)
	lib.is_valid_date(object.get(case_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(case_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "case/reviewed-stale",
		"message": "the erasure case was reviewed more than 365 days before today: this evidence is stale — a year-old sweep record says nothing about the copies made since",
		"path": "$.case.reviewedOn",
	}
}

# --- findings: the case must be readable ------------------------------------------

f_case_missing contains finding if {
	is_object(input)
	not is_object(case_doc)
	finding := {
		"severity": "error",
		"rule": "case/missing",
		"message": "the erasure case is required: pass it as input.case",
		"path": "$.case",
	}
}

f_case_content contains finding if {
	is_object(case_doc)
	not lib.is_nonempty_string(case_tenant)
	finding := {
		"severity": "error",
		"rule": "case/tenant-required",
		"message": "the erasure case must name the tenant (or subject) it erases: a case about nobody erases nobody",
		"path": "$.case.tenant",
	}
}

f_case_content contains finding if {
	is_object(case_doc)
	not lib.is_valid_date(case_requested_on)
	finding := {
		"severity": "error",
		"rule": "case/requested-on-invalid",
		"message": "the erasure case must carry requestedOn as a real YYYY-MM-DD date — the day the request arrived is the day the clock started",
		"path": "$.case.requestedOn",
	}
}

f_case_content contains finding if {
	is_object(case_doc)
	lib.is_valid_date(case_requested_on)
	lib.is_valid_date(today_date)
	lib.date_to_days(case_requested_on) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "case/requested-in-future",
		"message": "the erasure case carries a requestedOn date in the future: a request that has not arrived cannot have been served",
		"path": "$.case.requestedOn",
	}
}

f_case_content contains finding if {
	is_object(case_doc)
	not lib.is_nonempty_string(object.get(case_doc, "requestedBy", null))
	finding := {
		"severity": "error",
		"rule": "case/requested-by-required",
		"message": "the erasure case must name requestedBy: an erasure without a named request is deletion without cause",
		"path": "$.case.requestedBy",
	}
}

f_case_content contains finding if {
	is_object(case_doc)
	not case_status in {"open", "closed"}
	finding := {
		"severity": "error",
		"rule": "case/status-unknown",
		"message": sprintf("the erasure case must say open or closed: a case that is neither is a deletion claim with no state to check against its evidence (got '%s')", [case_status]),
		"path": "$.case.status",
	}
}

# --- findings: the storage inventory -----------------------------------------------

f_stores_array contains finding if {
	is_object(case_doc)
	not is_array(object.get(case_doc, "stores", null))
	finding := {
		"severity": "error",
		"rule": "stores/must-be-array",
		"message": "stores must be an array of {name, kind} inventory rows",
		"path": "$.case.stores",
	}
}

# The issue's own words: an incomplete inventory is a finding. The
# gate can only judge the stores the case declares — an empty
# inventory claims the data is nowhere, and that claim is the least
# believable one in the whole document.
f_stores_array contains finding if {
	is_object(case_doc)
	is_array(object.get(case_doc, "stores", null))
	count(stores) == 0
	finding := {
		"severity": "error",
		"rule": "stores/required",
		"message": "the erasure case must inventory at least one store: an empty inventory claims the data is nowhere — the inventory is where honesty starts",
		"path": "$.case.stores",
	}
}

f_stores_content contains finding if {
	some i, s in as_array(case_doc, "stores")
	not is_object(s)
	finding := {
		"severity": "error",
		"rule": "stores/row-must-be-object",
		"message": sprintf("store entry %d must be an object with name and kind", [i]),
		"path": sprintf("$.case.stores[%d]", [i]),
	}
}

f_stores_content contains finding if {
	some i, s in stores
	not lib.is_nonempty_string(store_name(s))
	finding := {
		"severity": "error",
		"rule": "store/name-required",
		"message": sprintf("store entry %d must carry a non-empty name: an unnamed store cannot be cited as swept", [i]),
		"path": sprintf("$.case.stores[%d].name", [i]),
	}
}

f_stores_content contains finding if {
	some i, s in stores
	lib.is_nonempty_string(store_name(s))
	not lib.is_nonempty_string(store_kind(s))
	finding := {
		"severity": "error",
		"rule": "store/kind-required",
		"message": sprintf("store '%s' must carry a non-empty kind: the kind is what tells a sweepable store from a window-bound backup", [store_name(s)]),
		"path": sprintf("$.case.stores[%d].kind", [i]),
	}
}

f_stores_content contains finding if {
	names := [store_name(s) |
		some s in stores
		store_row_well_formed(s)
	]
	some name in names
	count([n | some n in names; n == name]) > 1
	finding := {
		"severity": "error",
		"rule": "store/name-duplicate",
		"message": sprintf("store '%s' appears more than once in the inventory", [name]),
		"path": "$.case.stores",
	}
}

# --- findings: backups must declare their expiry windows ---------------------------

# A backup without a declared expiry window is a store that can never
# be proven gone: the window is what turns "we deleted some" into
# "every copy ages out by a date you can name".
f_backup_expiry contains finding if {
	some i, s in stores
	store_is_backup(s)
	not lib.is_valid_date(store_expires_on(s))
	finding := {
		"severity": "error",
		"rule": "store/backup-expiry-required",
		"message": sprintf("backup store '%s' must carry expiresOn as a real YYYY-MM-DD date: a backup without its expiry window never becomes provably gone", [store_name(s)]),
		"path": sprintf("$.case.stores[%d].expiresOn", [i]),
	}
}

# --- findings: the sweep records ----------------------------------------------------

f_sweeps_array contains finding if {
	is_object(case_doc)
	not is_array(object.get(case_doc, "sweeps", null))
	finding := {
		"severity": "error",
		"rule": "sweeps/must-be-array",
		"message": "sweeps must be an array of {store, sweptOn, sweptBy} records",
		"path": "$.case.sweeps",
	}
}

f_sweeps_content contains finding if {
	some i, w in as_array(case_doc, "sweeps")
	not is_object(w)
	finding := {
		"severity": "error",
		"rule": "sweeps/row-must-be-object",
		"message": sprintf("sweep entry %d must be an object with store, sweptOn, and sweptBy", [i]),
		"path": sprintf("$.case.sweeps[%d]", [i]),
	}
}

f_sweeps_content contains finding if {
	some i, w in sweeps
	not sweep_row_well_formed(w)
	finding := {
		"severity": "error",
		"rule": "sweep/row-invalid",
		"message": sprintf("sweep record %d must carry store (a non-empty string), sweptOn (a real YYYY-MM-DD date), and sweptBy (who or what swept it)", [i]),
		"path": sprintf("$.case.sweeps[%d]", [i]),
	}
}

f_sweep_refs contains finding if {
	some i, w in sweeps
	sweep_row_well_formed(w)
	not sweep_store(w) in store_names
	finding := {
		"severity": "error",
		"rule": "sweep/store-unknown",
		"message": sprintf("a sweep record covers '%s', which the inventory never declared: either the sweep is a record of nothing, or the inventory forgot a store — the two documents disagree", [sweep_store(w)]),
		"path": sprintf("$.case.sweeps[%d].store", [i]),
	}
}

# A sweep that predates the request it claims to serve: the record
# cannot close a case that had not opened.
f_sweep_refs contains finding if {
	some i, w in sweeps
	sweep_row_well_formed(w)
	lib.is_valid_date(case_requested_on)
	lib.date_to_days(sweep_on(w)) < lib.date_to_days(case_requested_on)
	finding := {
		"severity": "error",
		"rule": "sweep/before-request",
		"message": sprintf("store '%s' was swept on %s, before the erasure request arrived on %s: the record predates the case it claims to close", [sweep_store(w), sweep_on(w), case_requested_on]),
		"path": sprintf("$.case.sweeps[%d].sweptOn", [i]),
	}
}

f_sweep_refs contains finding if {
	some i, w in sweeps
	sweep_row_well_formed(w)
	lib.is_valid_date(sweep_on(w))
	lib.is_valid_date(today_date)
	lib.date_to_days(sweep_on(w)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "sweep/in-future",
		"message": sprintf("store '%s' was swept on %s, which is in the future: evidence cannot arrive before the work it evidences", [sweep_store(w), sweep_on(w)]),
		"path": sprintf("$.case.sweeps[%d].sweptOn", [i]),
	}
}

# --- findings: a store without a record — the issue's core rule --------------------

# The #69 rule, moved from alerting to erasure: nothing is forgotten
# without a record. A store in the inventory that no sweep record
# covers and no pending reason explains is the gap in the trail —
# erasure is evidence, not an assertion.
f_gate_stores contains finding if {
	some i, s in stores
	store_row_well_formed(s)
	not store_swept(s)
	not store_resolved(s)
	not store_pending(s)
	finding := {
		"severity": "error",
		"rule": "sweep/store-unswept",
		"message": sprintf("store '%s' is in the inventory but no sweep record covers it: nothing is forgotten without a record — erasure is evidence, not an assertion", [store_name(s)]),
		"path": sprintf("$.case.stores[%d]", [i]),
	}
}

# --- findings: the case must lean on the registry ---------------------------------

f_gate_keys contains finding if {
	is_object(case_doc)
	lib.is_nonempty_string(case_tenant)
	not tenant_registered(case_tenant)
	finding := {
		"severity": "error",
		"rule": "keys/tenant-unregistered",
		"message": sprintf("the DEK registry has no key for tenant '%s': a case without its registry row is a deletion claim with no primitive to stand on", [case_tenant]),
		"path": "$.case.tenant",
	}
}

f_gate_keys contains finding if {
	is_object(case_doc)
	lib.is_nonempty_string(case_tenant)
	tenant_registered(case_tenant)
	not tenant_deks_destroyed(case_tenant)
	k := first_live_key(case_tenant)
	finding := {
		"severity": "error",
		"rule": "keys/dek-not-destroyed",
		"message": sprintf("the registry still holds a live key for tenant '%s' (dek '%s', state '%s'): with the key alive the ciphertext is readable, and the erasure is a promise", [case_tenant, key_dek(k), key_state(k)]),
		"path": sprintf("$.keys.keys[%d]", [key_index(key_dek(k))]),
	}
}

# --- findings: the case's own status, judged against its evidence -------------------

f_gate_case contains finding if {
	is_object(case_doc)
	case_status == "closed"
	some s in stores
	store_pending(s)
	detail := pending_detail(s)
	finding := {
		"severity": "error",
		"rule": "case/closed-early",
		"message": sprintf("the case says closed, but store '%s' is still pending (%s): nothing is forgotten while a store can still produce the data — let the window close first", [store_name(s), detail]),
		"path": "$.case.status",
	}
}

# The mirror image: a case left open with no remaining work is a
# record nobody finished. It warns, honestly — the evidence is sound.
f_gate_case contains finding if {
	is_object(case_doc)
	case_status == "open"
	case_complete
	finding := {
		"severity": "warning",
		"rule": "case/closable",
		"message": "every store is swept or aged out and the tenant's keys are destroyed: this case can close honestly — an open case with no remaining work is a record nobody finished",
		"path": "$.case.status",
	}
}

# --- store resolution: the verdict the playground renders ---------------------------

# One card per well-formed inventory store, sorted by store name:
# swept (with the day), expired (the backup aged out), pending (the
# window or the reason), or unswept (no record, no reason).
store_cards := [card |
	name := sort({store_name(s) |
		some s in stores
		store_row_well_formed(s)
	})[_]
	card := {
		"store": name,
		"verdict": store_verdict(first_store_named(name)),
		"detail": store_detail(first_store_named(name)),
	}
]

# The first well-formed inventory row with this name, in document
# order — the row the card judges, deterministically.
first_store_named(name) := s if {
	matches := [s |
		some s in stores
		store_row_well_formed(s)
		store_name(s) == name
	]
	count(matches) > 0
	s := matches[0]
}

store_verdict(s) := "swept" if store_swept(s)

store_verdict(s) := "expired" if {
	not store_swept(s)
	backup_expired(s)
}

store_verdict(s) := "pending" if {
	not store_swept(s)
	not backup_expired(s)
	store_pending(s)
}

store_verdict(s) := "unswept" if {
	not store_swept(s)
	not backup_expired(s)
	not store_pending(s)
}

store_detail(s) := sprintf("swept on %s", [sweep_on(first_sweep(store_name(s)))]) if store_swept(s)

store_detail(s) := sprintf("backup aged out on %s", [store_expires_on(s)]) if {
	not store_swept(s)
	backup_expired(s)
}

store_detail(s) := pending_detail(s) if {
	not store_swept(s)
	not backup_expired(s)
	store_pending(s)
}

store_detail(s) := "no sweep record and no pending reason" if {
	not store_swept(s)
	not backup_expired(s)
	not store_pending(s)
}

# The pending detail: the open window with its date, or the declared
# reason in the case's own words.
pending_detail(s) := sprintf("backup window open until %s", [store_expires_on(s)]) if backup_window_open(s)

pending_detail(s) := store_pending_reason(s) if {
	not backup_window_open(s)
	store_pending_by_reason(s)
}

# The first well-formed sweep record covering a store, in document
# order — the record the card cites, deterministically.
first_sweep(name) := w if {
	matches := sweeps_for(name)
	count(matches) > 0
	w := matches[0]
}

# --- the case verdict ------------------------------------------------------------

case_pending if {
	some s in stores
	store_pending(s)
}

# A case is complete when every well-formed store is resolved, the
# tenant is registered, and all its keys are destroyed.
case_complete if {
	every s in stores {
		store_row_well_formed(s)
		store_resolved(s)
	}
	lib.is_nonempty_string(case_tenant)
	tenant_registered(case_tenant)
	tenant_deks_destroyed(case_tenant)
}

case_verdict(fs) := "incomplete" if {
	count([f | f := fs[_]; f.severity == "error"]) > 0
}

case_verdict(fs) := "pending, honest" if {
	count([f | f := fs[_]; f.severity == "error"]) == 0
	case_pending
}

case_verdict(fs) := "forgotten" if {
	count([f | f := fs[_]; f.severity == "error"]) == 0
	not case_pending
}

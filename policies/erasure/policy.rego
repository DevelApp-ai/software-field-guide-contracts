# DEK registry validator — The Software Field Guide, issue #79.
#
# Judges the per-tenant DEK registry on its own: named keys for named
# tenants, each with its state, and — when the state is destroyed —
# the day it died and what destroyed it. Key destruction is the
# book's strongest verified deletion primitive; a registry row that
# claims a destruction without its evidence record is a deletion
# asserted, not evidenced. The registry is the promise the erasure
# case leans on; the case gate judges the evidence that everything
# else followed the key into the dark.
#
# Input (JSON): {"keys": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [{severity, rule, message, path}]}
package erasure

import rego.v1

import data.erasure.lib

# --- entrypoint -------------------------------------------------------------

validate := result if {
	fs := sort([f | some f in validate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
	}
}

validate_findings := ((((((((f_input_invalid | f_today_invalid) | f_keys_missing) | f_version) | f_reviewed) | f_keys_array) | f_keys_content) | f_key_content) | f_key_state) | f_key_evidence

# --- findings: input shape -----------------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the DEK registry as input.keys",
		"path": "$",
	}
}

f_today_invalid contains finding if {
	is_object(input)
	not lib.is_valid_date(object.get(input, "today", null))
	finding := {
		"severity": "error",
		"rule": "input/today-invalid",
		"message": "today must be a real YYYY-MM-DD date — the clock is injected, never read",
		"path": "$.today",
	}
}

# --- findings: the document is missing --------------------------------------------

f_keys_missing contains finding if {
	not is_object(keys_doc)
	finding := {
		"severity": "error",
		"rule": "keys/missing",
		"message": "the DEK registry is required: pass it as input.keys",
		"path": "$.keys",
	}
}

# --- findings: version and review stamps -------------------------------------------

# The registry is versioned like code and re-read like every other
# owned document: a key table nobody re-reads is a key table nobody
# still believes.
f_version contains finding if {
	is_object(keys_doc)
	not is_positive_integer(object.get(keys_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "keys/version-required",
		"message": "the DEK registry must carry a version (a positive integer): the key table is versioned like code",
		"path": "$.keys.version",
	}
}

f_reviewed contains finding if {
	is_object(keys_doc)
	not lib.is_valid_date(object.get(keys_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "keys/reviewed-on-invalid",
		"message": "the DEK registry must carry reviewedOn as a real YYYY-MM-DD date",
		"path": "$.keys.reviewedOn",
	}
}

f_reviewed contains finding if {
	is_object(keys_doc)
	lib.is_valid_date(object.get(keys_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(keys_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "keys/reviewed-in-future",
		"message": "the DEK registry carries a reviewedOn date in the future",
		"path": "$.keys.reviewedOn",
	}
}

f_reviewed contains finding if {
	is_object(keys_doc)
	lib.is_valid_date(object.get(keys_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(keys_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "keys/reviewed-stale",
		"message": "the DEK registry was reviewed more than 365 days before today: this document is stale",
		"path": "$.keys.reviewedOn",
	}
}

is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# --- findings: the key rows --------------------------------------------------------

f_keys_array contains finding if {
	is_object(keys_doc)
	not is_array(object.get(keys_doc, "keys", null))
	finding := {
		"severity": "error",
		"rule": "keys/must-be-array",
		"message": "keys must be an array of {dek, tenant, state, destroyedAt, destroyedBy} rows",
		"path": "$.keys.keys",
	}
}

f_keys_array contains finding if {
	is_object(keys_doc)
	is_array(object.get(keys_doc, "keys", null))
	count(key_rows) == 0
	finding := {
		"severity": "error",
		"rule": "keys/required",
		"message": "the DEK registry must carry at least one key row: an empty registry erases nobody",
		"path": "$.keys.keys",
	}
}

f_keys_content contains finding if {
	some i, k in as_array(keys_doc, "keys")
	not is_object(k)
	finding := {
		"severity": "error",
		"rule": "keys/row-must-be-object",
		"message": sprintf("registry row %d must be an object with dek, tenant, and state", [i]),
		"path": sprintf("$.keys.keys[%d]", [i]),
	}
}

f_key_content contains finding if {
	some i, k in key_rows
	not lib.is_nonempty_string(key_dek(k))
	finding := {
		"severity": "error",
		"rule": "key/dek-required",
		"message": sprintf("registry row %d must carry a non-empty dek: an unnamed key cannot be cited as evidence", [i]),
		"path": sprintf("$.keys.keys[%d].dek", [i]),
	}
}

f_key_content contains finding if {
	some i, k in key_rows
	lib.is_nonempty_string(key_dek(k))
	not lib.is_nonempty_string(key_tenant(k))
	finding := {
		"severity": "error",
		"rule": "key/tenant-required",
		"message": sprintf("key '%s' must name its tenant: a key that belongs to nobody guards nobody", [key_dek(k)]),
		"path": sprintf("$.keys.keys[%d].tenant", [i]),
	}
}

# --- findings: key state and destruction evidence ---------------------------------

f_key_state contains finding if {
	some i, k in key_rows
	key_row_well_formed(k)
	not key_state(k) in {"active", "destroyed"}
	finding := {
		"severity": "error",
		"rule": "key/state-unknown",
		"message": sprintf("key '%s' carries state '%s', which is neither active nor destroyed: the registry must say what the key is, not shrug", [key_dek(k), key_state(k)]),
		"path": sprintf("$.keys.keys[%d].state", [i]),
	}
}

# The destruction evidence: a destroyed key without the day it died
# and the change that killed it is a deletion asserted, not evidenced.
f_key_evidence contains finding if {
	some i, k in key_rows
	key_row_well_formed(k)
	key_state(k) == "destroyed"
	not lib.is_valid_date(key_destroyed_at(k))
	finding := {
		"severity": "error",
		"rule": "key/destroyed-at-invalid",
		"message": sprintf("key '%s' is marked destroyed but its destroyedAt is not a real YYYY-MM-DD date — a destruction without its day is a rumor", [key_dek(k)]),
		"path": sprintf("$.keys.keys[%d].destroyedAt", [i]),
	}
}

f_key_evidence contains finding if {
	some i, k in key_rows
	key_row_well_formed(k)
	key_state(k) == "destroyed"
	lib.is_valid_date(key_destroyed_at(k))
	lib.is_valid_date(today_date)
	lib.date_to_days(key_destroyed_at(k)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "key/destroyed-in-future",
		"message": sprintf("key '%s' is marked destroyed on %s, which is in the future: a destruction cannot predate the clock that certifies it", [key_dek(k), key_destroyed_at(k)]),
		"path": sprintf("$.keys.keys[%d].destroyedAt", [i]),
	}
}

f_key_evidence contains finding if {
	some i, k in key_rows
	key_row_well_formed(k)
	key_state(k) == "destroyed"
	not lib.is_nonempty_string(key_destroyed_by(k))
	finding := {
		"severity": "error",
		"rule": "key/destroyed-by-required",
		"message": sprintf("key '%s' is marked destroyed but names no destroyedBy: destruction needs its evidence record — the change, the runbook, the hand that did it", [key_dek(k)]),
		"path": sprintf("$.keys.keys[%d].destroyedBy", [i]),
	}
}

# A key marked active with destruction evidence attached contradicts
# itself: the state and the record disagree, and the registry cannot
# be trusted on either.
f_key_evidence contains finding if {
	some i, k in key_rows
	key_row_well_formed(k)
	key_state(k) == "active"
	or_evidence(k)
	finding := {
		"severity": "error",
		"rule": "key/active-with-evidence",
		"message": sprintf("key '%s' is marked active but carries destruction evidence: the state and the record disagree — which one is the registry lying about?", [key_dek(k)]),
		"path": sprintf("$.keys.keys[%d]", [i]),
	}
}

or_evidence(k) if lib.is_nonempty_string(key_destroyed_at(k))

or_evidence(k) if lib.is_nonempty_string(key_destroyed_by(k))

# --- findings: the same key twice ---------------------------------------------------

f_key_content contains finding if {
	deks := [key_dek(k) |
		some k in key_rows
		key_row_well_formed(k)
	]
	some dek in deks
	count([d | some d in deks; d == dek]) > 1
	finding := {
		"severity": "error",
		"rule": "key/dek-duplicate",
		"message": sprintf("key '%s' appears more than once in the registry", [dek]),
		"path": "$.keys.keys",
	}
}

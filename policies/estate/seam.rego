# Seam contract validator — The Software Field Guide, "Segmenting the Estate".
#
# A seam contract is six answers plus a rehearsal date: where traffic and
# identity arrive, who gets in and who is denied, how the seam is watched,
# what happens when it fails, how it is shut down — and when you last
# proved all of that by rehearsing the kill path. This policy checks the
# six answers plus the two dates against the house rules from the chapter.
#
# Input (JSON): {"contract": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [{severity, rule, message, path}]}
package estate.seam

import rego.v1

import data.estate.lib

# --- input ----------------------------------------------------------------

contract := object.get(input, "contract", null) if is_object(input)

contract_present if is_object(contract)

today := object.get(input, "today", null) if is_object(input)

# --- validation -----------------------------------------------------------

validate := result if {
	fs := sort([f | findings[f]])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
	}
}

# --- findings: input shape ------------------------------------------------

findings contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with 'contract' and 'today' fields",
		"path": "$",
	}
}

findings contains finding if {
	is_object(input)
	not lib.is_valid_date(today)
	finding := {
		"severity": "error",
		"rule": "input/today-invalid",
		"message": "today is missing or not a valid calendar date in YYYY-MM-DD format",
		"path": "$.today",
	}
}

findings contains finding if {
	is_object(input)
	not contract_present
	finding := {
		"severity": "error",
		"rule": "contract/missing",
		"message": "contract is missing or not an object",
		"path": "$.contract",
	}
}

# --- findings: required string fields --------------------------------------

required_string_fields := {
	"seam": "seam name",
	"enclave": "owning enclave",
	"entry": "entry (how traffic and identity arrive)",
	"decision": "decision (who gets in, who is denied)",
	"monitoring": "monitoring (how you watch the seam)",
	"blastRadius": "blast radius (what it means when this seam fails)",
	"killPath": "kill path (how you shut the seam down)",
	"lastRehearsed": "last rehearsal date",
	"reviewDate": "next review date",
}

findings contains finding if {
	contract_present
	some field, label in required_string_fields
	not lib.is_nonempty_string(object.get(contract, field, null))
	finding := {
		"severity": "error",
		"rule": "contract/required-field-missing",
		"message": sprintf("%s is required: it must be a non-empty string", [label]),
		"path": sprintf("$.contract.%s", [field]),
	}
}

# --- findings: keyword warnings ---------------------------------------------
#
# The chapter's rule of thumb: an entry with no named identity mechanism is
# an open door, a decision with no deny is hope rather than policy, and
# monitoring that names no observation is not monitoring.

entry_identity_keywords := {"auth", "mtls", "svid", "token", "identity"}

findings contains finding if {
	contract_present
	entry := object.get(contract, "entry", null)
	lib.is_nonempty_string(entry)
	not text_mentions_any(lower(entry), entry_identity_keywords)
	finding := {
		"severity": "warning",
		"rule": "contract/entry-no-identity-mechanism",
		"message": "entry does not name an identity mechanism (auth, mTLS, SVID, token, or identity)",
		"path": "$.contract.entry",
	}
}

findings contains finding if {
	contract_present
	decision := object.get(contract, "decision", null)
	lib.is_nonempty_string(decision)
	not contains(lower(decision), "deny")
	finding := {
		"severity": "warning",
		"rule": "contract/decision-no-deny-rule",
		"message": "decision does not state a deny rule: without a deny there is no policy, only hope",
		"path": "$.contract.decision",
	}
}

monitoring_keywords := {"log", "metric", "alert", "monitor"}

findings contains finding if {
	contract_present
	monitoring := object.get(contract, "monitoring", null)
	lib.is_nonempty_string(monitoring)
	not text_mentions_any(lower(monitoring), monitoring_keywords)
	finding := {
		"severity": "warning",
		"rule": "contract/monitoring-not-stated",
		"message": "monitoring does not say how the seam is observed (log, metric, alert, or monitor)",
		"path": "$.contract.monitoring",
	}
}

text_mentions_any(text, keywords) if {
	some keyword in keywords
	contains(text, keyword)
}

# --- findings: rehearsal date -------------------------------------------------

last_rehearsed := object.get(contract, "lastRehearsed", null) if contract_present

findings contains finding if {
	contract_present
	is_string(last_rehearsed)
	not lib.is_valid_date(last_rehearsed)
	finding := {
		"severity": "error",
		"rule": "contract/last-rehearsed-invalid",
		"message": "lastRehearsed must be a valid calendar date in YYYY-MM-DD format",
		"path": "$.contract.lastRehearsed",
	}
}

findings contains finding if {
	contract_present
	lib.is_valid_date(today)
	lib.is_valid_date(last_rehearsed)
	lib.date_to_days(last_rehearsed) > lib.date_to_days(today)
	finding := {
		"severity": "error",
		"rule": "contract/last-rehearsed-in-future",
		"message": "lastRehearsed lies in the future: a rehearsal that has not happened is a plan, not a rehearsal",
		"path": "$.contract.lastRehearsed",
	}
}

findings contains finding if {
	contract_present
	lib.is_valid_date(today)
	lib.is_valid_date(last_rehearsed)
	lib.date_to_days(today) - lib.date_to_days(last_rehearsed) > 180
	finding := {
		"severity": "error",
		"rule": "contract/last-rehearsed-stale",
		"message": "lastRehearsed is more than 180 days before today: an unrehearsed seam contract is stale",
		"path": "$.contract.lastRehearsed",
	}
}

# --- findings: next review date -----------------------------------------------

review_date := object.get(contract, "reviewDate", null) if contract_present

findings contains finding if {
	contract_present
	is_string(review_date)
	not lib.is_valid_date(review_date)
	finding := {
		"severity": "error",
		"rule": "contract/review-date-invalid",
		"message": "reviewDate must be a valid calendar date in YYYY-MM-DD format",
		"path": "$.contract.reviewDate",
	}
}

findings contains finding if {
	contract_present
	lib.is_valid_date(today)
	lib.is_valid_date(review_date)
	lib.date_to_days(review_date) < lib.date_to_days(today)
	finding := {
		"severity": "error",
		"rule": "contract/review-overdue",
		"message": "reviewDate is before today: the next review is already overdue",
		"path": "$.contract.reviewDate",
	}
}

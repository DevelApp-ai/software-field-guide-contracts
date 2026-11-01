# Segment contract validator — The Software Field Guide, issue #80.
#
# Judges the segment contract on its own: the segments it declares,
# the rules between them — each named, its segments declared, its
# direction, type, and port inside the modeled subset, its mode audit
# or enforce — and its TTL-bound exceptions, each carrying a reason
# and a real expiry date that has not passed. A contract is the one
# document every fabric renders; a contract row that cannot be read
# cannot be rendered anywhere. The honesty is structural: the
# validator models a subset of the policy languages (direction, type,
# port) and says so in its findings, never pretending to full eBPF
# or CIL semantics.
#
# Input (JSON): {"contract": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [{severity, rule, message, path}]}
package segment

import rego.v1

import data.segment.lib

# --- entrypoint -------------------------------------------------------------

validate := result if {
	fs := sort([f | some f in validate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
	}
}

validate_findings := ((((((((((((f_input_invalid | f_today_invalid) | f_contract_missing) | f_contract_stamps) | f_segments_array) | f_segments_content) | f_rules_array) | f_rules_content) | f_rule_content) | f_rule_refs) | f_rule_dupes) | f_exceptions_array) | f_exception_content) | f_exception_ttl

# --- findings: input shape -----------------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the segment contract as input.contract",
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

f_contract_missing contains finding if {
	not is_object(contract_doc)
	finding := {
		"severity": "error",
		"rule": "contract/missing",
		"message": "the segment contract is required: pass it as input.contract",
		"path": "$.contract",
	}
}

# --- findings: version and review stamps -------------------------------------------

# The contract is versioned like code and re-read like every other
# owned document: a rule table nobody re-reads is a rule table nobody
# still believes.
f_contract_stamps contains finding if {
	is_object(contract_doc)
	not is_positive_integer(object.get(contract_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "contract/version-required",
		"message": "the segment contract must carry a version (a positive integer): the rule table is versioned like code",
		"path": "$.contract.version",
	}
}

f_contract_stamps contains finding if {
	is_object(contract_doc)
	not lib.is_valid_date(object.get(contract_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "contract/reviewed-on-invalid",
		"message": "the segment contract must carry reviewedOn as a real YYYY-MM-DD date",
		"path": "$.contract.reviewedOn",
	}
}

f_contract_stamps contains finding if {
	is_object(contract_doc)
	lib.is_valid_date(object.get(contract_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(contract_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "contract/reviewed-in-future",
		"message": "the segment contract carries a reviewedOn date in the future",
		"path": "$.contract.reviewedOn",
	}
}

f_contract_stamps contains finding if {
	is_object(contract_doc)
	lib.is_valid_date(object.get(contract_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(contract_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "contract/reviewed-stale",
		"message": "the segment contract was reviewed more than 365 days before today: this rule table is stale — a year-old contract says nothing about the estate rendered since",
		"path": "$.contract.reviewedOn",
	}
}

f_contract_stamps contains finding if {
	is_object(contract_doc)
	not lib.is_nonempty_string(object.get(contract_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "contract/owner-required",
		"message": "the segment contract must name an owner: a rule table with an owner and a review cadence is the discipline",
		"path": "$.contract.owner",
	}
}

# --- findings: the segments -----------------------------------------------------

f_segments_array contains finding if {
	is_object(contract_doc)
	not is_array(object.get(contract_doc, "segments", null))
	finding := {
		"severity": "error",
		"rule": "segments/must-be-array",
		"message": "segments must be an array of segment names",
		"path": "$.contract.segments",
	}
}

f_segments_array contains finding if {
	is_object(contract_doc)
	is_array(object.get(contract_doc, "segments", null))
	count(segments) == 0
	finding := {
		"severity": "error",
		"rule": "segments/required",
		"message": "the segment contract must declare at least one segment: an estate of no segments segments nothing",
		"path": "$.contract.segments",
	}
}

f_segments_content contains finding if {
	some i, s in as_array(contract_doc, "segments")
	not is_string(s)
	finding := {
		"severity": "error",
		"rule": "segment/must-be-string",
		"message": sprintf("segment entry %d must be a non-empty string naming the segment", [i]),
		"path": sprintf("$.contract.segments[%d]", [i]),
	}
}

f_segments_content contains finding if {
	some i, s in as_array(contract_doc, "segments")
	is_string(s)
	not lib.is_nonempty_string(s)
	finding := {
		"severity": "error",
		"rule": "segment/name-required",
		"message": sprintf("segment entry %d must carry a non-empty name: an unnamed segment cannot be cited in a rule", [i]),
		"path": sprintf("$.contract.segments[%d]", [i]),
	}
}

f_segments_content contains finding if {
	some name in segments
	lib.is_nonempty_string(name)
	count([s | some s in segments; s == name]) > 1
	finding := {
		"severity": "error",
		"rule": "segment/name-duplicate",
		"message": sprintf("segment '%s' is declared more than once in the contract", [name]),
		"path": "$.contract.segments",
	}
}

# --- findings: the rules --------------------------------------------------------

f_rules_array contains finding if {
	is_object(contract_doc)
	not is_array(object.get(contract_doc, "rules", null))
	finding := {
		"severity": "error",
		"rule": "rules/must-be-array",
		"message": "rules must be an array of {id, from, to, type, port, direction, mode} rows",
		"path": "$.contract.rules",
	}
}

f_rules_array contains finding if {
	is_object(contract_doc)
	is_array(object.get(contract_doc, "rules", null))
	count(rules) == 0
	finding := {
		"severity": "error",
		"rule": "rules/required",
		"message": "the segment contract must carry at least one rule: a contract with no rules allows and denies nothing on purpose",
		"path": "$.contract.rules",
	}
}

f_rules_content contains finding if {
	some i, r in as_array(contract_doc, "rules")
	not is_object(r)
	finding := {
		"severity": "error",
		"rule": "rules/row-must-be-object",
		"message": sprintf("rule entry %d must be an object with id, from, to, type, port, direction, and mode", [i]),
		"path": sprintf("$.contract.rules[%d]", [i]),
	}
}

# --- findings: rule content — named rules between declared segments ---------------

f_rule_content contains finding if {
	some i, r in rules
	not lib.is_nonempty_string(rule_id(r))
	finding := {
		"severity": "error",
		"rule": "rule/id-required",
		"message": sprintf("contract rule %d must carry a non-empty id: an unnamed rule cannot be cited by a render or a promotion", [i]),
		"path": sprintf("$.contract.rules[%d].id", [i]),
	}
}

f_rule_content contains finding if {
	some i, r in rules
	lib.is_nonempty_string(rule_id(r))
	not lib.is_nonempty_string(rule_from(r))
	finding := {
		"severity": "error",
		"rule": "rule/from-required",
		"message": sprintf("rule '%s' must name its from segment: a rule that starts nowhere guards nowhere", [rule_id(r)]),
		"path": sprintf("$.contract.rules[%d].from", [i]),
	}
}

f_rule_content contains finding if {
	some i, r in rules
	lib.is_nonempty_string(rule_id(r))
	not lib.is_nonempty_string(rule_to(r))
	finding := {
		"severity": "error",
		"rule": "rule/to-required",
		"message": sprintf("rule '%s' must name its to segment: a rule that goes nowhere allows nothing", [rule_id(r)]),
		"path": sprintf("$.contract.rules[%d].to", [i]),
	}
}

# The join the contract owes its renders: a rule between segments the
# contract never declared cites estates nobody modeled.
f_rule_refs contains finding if {
	some i, r in rules
	lib.is_nonempty_string(rule_id(r))
	lib.is_nonempty_string(rule_from(r))
	not segment_named(rule_from(r))
	finding := {
		"severity": "error",
		"rule": "rule/segment-undeclared",
		"message": sprintf("rule '%s' leaves from segment '%s', which the contract never declared: a rule between undeclared segments is a rule about an estate nobody modeled", [rule_id(r), rule_from(r)]),
		"path": sprintf("$.contract.rules[%d].from", [i]),
	}
}

f_rule_refs contains finding if {
	some i, r in rules
	lib.is_nonempty_string(rule_id(r))
	lib.is_nonempty_string(rule_to(r))
	not segment_named(rule_to(r))
	finding := {
		"severity": "error",
		"rule": "rule/segment-undeclared",
		"message": sprintf("rule '%s' enters segment '%s', which the contract never declared: a rule between undeclared segments is a rule about an estate nobody modeled", [rule_id(r), rule_to(r)]),
		"path": sprintf("$.contract.rules[%d].to", [i]),
	}
}

# The modeled subset, enforced honestly: tcp and udp, ingress and
# egress, audit and enforce — anything else is a rule the gate cannot
# verify, and an unverifiable rule is a rule that drifts by default.
f_rule_content contains finding if {
	some i, r in rules
	lib.is_nonempty_string(rule_id(r))
	not rule_type(r) in modeled_types
	finding := {
		"severity": "error",
		"rule": "rule/type-unknown",
		"message": sprintf("rule '%s' carries type '%s', which is outside the modeled subset (tcp, udp): the gate verifies what it models and says so — not full eBPF or CIL semantics", [rule_id(r), rule_type(r)]),
		"path": sprintf("$.contract.rules[%d].type", [i]),
	}
}

f_rule_content contains finding if {
	some i, r in rules
	lib.is_nonempty_string(rule_id(r))
	not is_valid_port(rule_port(r))
	finding := {
		"severity": "error",
		"rule": "rule/port-invalid",
		"message": sprintf("rule '%s' carries a port that is not an integer from 1 to 65535 (got %s): a rule that names no real port renders to no real fabric", [rule_id(r), json.marshal(rule_port(r))]),
		"path": sprintf("$.contract.rules[%d].port", [i]),
	}
}

f_rule_content contains finding if {
	some i, r in rules
	lib.is_nonempty_string(rule_id(r))
	not rule_direction(r) in modeled_directions
	finding := {
		"severity": "error",
		"rule": "rule/direction-unknown",
		"message": sprintf("rule '%s' carries direction '%s', which is neither ingress nor egress: the contract must say which way the traffic flows, not shrug", [rule_id(r), rule_direction(r)]),
		"path": sprintf("$.contract.rules[%d].direction", [i]),
	}
}

f_rule_content contains finding if {
	some i, r in rules
	lib.is_nonempty_string(rule_id(r))
	not rule_mode(r) in modeled_modes
	finding := {
		"severity": "error",
		"rule": "rule/mode-unknown",
		"message": sprintf("rule '%s' carries mode '%s', which is neither audit nor enforce: a rule that is neither is observed by nobody and enforced by nobody", [rule_id(r), rule_mode(r)]),
		"path": sprintf("$.contract.rules[%d].mode", [i]),
	}
}

# --- findings: the same rule twice ------------------------------------------------

f_rule_dupes contains finding if {
	ids := [rule_id(r) |
		some r in rules
		lib.is_nonempty_string(rule_id(r))
	]
	some id in ids
	count([x | some x in ids; x == id]) > 1
	finding := {
		"severity": "error",
		"rule": "rule/id-duplicate",
		"message": sprintf("rule '%s' appears more than once in the contract: two rules with one id is a render that cannot know which row it renders", [id]),
		"path": "$.contract.rules",
	}
}

# --- findings: the TTL-bound exceptions --------------------------------------------

f_exceptions_array contains finding if {
	some i, r in rules
	rule_row_well_formed(r)
	not is_array(object.get(r, "exceptions", []))
	finding := {
		"severity": "error",
		"rule": "exceptions/must-be-array",
		"message": sprintf("rule '%s' carries exceptions that are not an array of {reason, expiresOn} rows", [rule_id(r)]),
		"path": sprintf("$.contract.rules[%d].exceptions", [i]),
	}
}

f_exceptions_array contains finding if {
	some i, e in exception_pairs
	not is_object(e.row)
	finding := {
		"severity": "error",
		"rule": "exceptions/row-must-be-object",
		"message": sprintf("rule '%s' carries an exception entry that is not an object with reason and expiresOn", [e.rule]),
		"path": sprintf("$.contract.rules[%d].exceptions[%d]", [e.index, e.position]),
	}
}

exception_pairs := [{"rule": rule_id(r), "index": i, "position": p, "row": e} |
	some i, r in rules
	some p, e in as_array(r, "exceptions")
]

f_exception_content contains finding if {
	some e in exception_pairs
	is_object(e.row)
	not lib.is_nonempty_string(exception_reason(e.row))
	finding := {
		"severity": "error",
		"rule": "exception/reason-required",
		"message": sprintf("an exception on rule '%s' carries no reason: an exception without its reason in words is a hole in the contract nobody can audit", [e.rule]),
		"path": sprintf("$.contract.rules[%d].exceptions[%d].reason", [e.index, e.position]),
	}
}

# An exception without its expiry date is a rule state that never
# ends — the TTL is what makes an exception temporary.
f_exception_content contains finding if {
	some e in exception_pairs
	is_object(e.row)
	not lib.is_valid_date(exception_expires_on(e.row))
	finding := {
		"severity": "error",
		"rule": "exception/expiry-required",
		"message": sprintf("an exception on rule '%s' must carry expiresOn as a real YYYY-MM-DD date: an exception is TTL-bound by design — without its expiry it is not an exception, it is the rule", [e.rule]),
		"path": sprintf("$.contract.rules[%d].exceptions[%d].expiresOn", [e.index, e.position]),
	}
}

# A TTL-bound exception whose window has passed: the contract still
# carries the exception, but the clock has retired it — the exception
# is dead weight, and a rendered estate that still honors it enforces
# a promise that expired.
f_exception_ttl contains finding if {
	some e in exception_pairs
	exception_row_well_formed(e.row)
	lib.is_valid_date(today_date)
	lib.date_to_days(exception_expires_on(e.row)) <= lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "exception/ttl-expired",
		"message": sprintf("the exception on rule '%s' (\"%s\") expired on %s, which has passed: remove it or renew its TTL — an expired exception rendered is a promise the clock already broke", [e.rule, exception_reason(e.row), exception_expires_on(e.row)]),
		"path": sprintf("$.contract.rules[%d].exceptions[%d].expiresOn", [e.index, e.position]),
	}
}

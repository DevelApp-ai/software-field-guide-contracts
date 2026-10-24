# Alerting contract validator — The Software Field Guide, issue #69.
#
# Judges the alerting contract on its own: the severity ladder (each
# rung defined on a real date, before it could be used), the runbooks
# (each with its escalation clock — "who escalates, by when" is part of
# the contract, not of the incident), and the alert rules (each with an
# owner, a severity on the ladder, a runbook, and a record destination).
# The contract is the promise made before anything pages; the register
# gate judges the evidence of what happened after.
#
# Input (JSON): {"alerting": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [{severity, rule, message, path}]}
package alerts

import rego.v1

import data.alerts.lib

# --- entrypoint -------------------------------------------------------------

validate := result if {
	fs := sort([f | some f in validate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
	}
}

validate_findings := (((((((((f_input_invalid | f_today_invalid) | f_alerting_missing) | f_version) | f_reviewed) | f_ladder) | f_runbooks) | f_runbook_content) | f_alerts_array) | f_alert_content) | f_alert_refs

# --- findings: input shape -----------------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the alerting contract as input.alerting",
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

f_alerting_missing contains finding if {
	not is_object(alerting_doc)
	finding := {
		"severity": "error",
		"rule": "alerting/missing",
		"message": "the alerting contract is required: pass it as input.alerting",
		"path": "$.alerting",
	}
}

# --- findings: version and review stamps -------------------------------------------

# The alerting contract is versioned like code: an alert set whose
# ladder and runbooks can silently change is folklore, not a contract.
f_version contains finding if {
	is_object(alerting_doc)
	not is_positive_integer(object.get(alerting_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "alerting/version-required",
		"message": "the alerting contract must carry a version (a positive integer): the ladder and runbooks are versioned like code",
		"path": "$.alerting.version",
	}
}

f_reviewed contains finding if {
	is_object(alerting_doc)
	not lib.is_valid_date(object.get(alerting_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "alerting/reviewed-on-invalid",
		"message": "the alerting contract must carry reviewedOn as a real YYYY-MM-DD date",
		"path": "$.alerting.reviewedOn",
	}
}

f_reviewed contains finding if {
	is_object(alerting_doc)
	lib.is_valid_date(object.get(alerting_doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(alerting_doc, "reviewedOn", null)) > lib.date_to_days(object.get(input, "today", null))
	finding := {
		"severity": "error",
		"rule": "alerting/reviewed-in-future",
		"message": "the alerting contract carries a reviewedOn date in the future",
		"path": "$.alerting.reviewedOn",
	}
}

f_reviewed contains finding if {
	is_object(alerting_doc)
	lib.is_valid_date(object.get(alerting_doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(input, "today", null)) - lib.date_to_days(object.get(alerting_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "alerting/reviewed-stale",
		"message": "the alerting contract was reviewed more than 365 days before today: this document is stale",
		"path": "$.alerting.reviewedOn",
	}
}

is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# --- findings: the severity ladder ----------------------------------------------

f_ladder contains finding if {
	is_object(alerting_doc)
	not is_array(object.get(alerting_doc, "severityLadder", null))
	finding := {
		"severity": "error",
		"rule": "ladder/must-be-array",
		"message": "severityLadder must be an array of {name, description, definedOn} rungs",
		"path": "$.alerting.severityLadder",
	}
}

f_ladder contains finding if {
	is_object(alerting_doc)
	is_array(object.get(alerting_doc, "severityLadder", null))
	count(ladder_rungs) == 0
	finding := {
		"severity": "error",
		"rule": "ladder/required",
		"message": "the severity ladder must define at least one rung: an alert's severity must be a defined fact, not a judgment call made at 3 a.m.",
		"path": "$.alerting.severityLadder",
	}
}

f_ladder contains finding if {
	some i, r in as_array(alerting_doc, "severityLadder")
	not is_object(r)
	finding := {
		"severity": "error",
		"rule": "ladder/rung-must-be-object",
		"message": sprintf("ladder rung %d must be an object with name, description, and definedOn", [i]),
		"path": sprintf("$.alerting.severityLadder[%d]", [i]),
	}
}

f_ladder contains finding if {
	some i, r in ladder_rungs
	not lib.is_nonempty_string(object.get(r, "name", null))
	finding := {
		"severity": "error",
		"rule": "ladder/name-required",
		"message": sprintf("ladder rung %d must carry a non-empty name", [i]),
		"path": sprintf("$.alerting.severityLadder[%d].name", [i]),
	}
}

f_ladder contains finding if {
	some i, r in ladder_rungs
	lib.is_nonempty_string(object.get(r, "name", null))
	not lib.is_nonempty_string(object.get(r, "description", null))
	finding := {
		"severity": "error",
		"rule": "ladder/description-required",
		"message": sprintf("ladder rung '%s' must carry a non-empty description: a severity nobody can define is a severity nobody can assign", [object.get(r, "name", null)]),
		"path": sprintf("$.alerting.severityLadder[%d].description", [i]),
	}
}

f_ladder contains finding if {
	some i, r in ladder_rungs
	not lib.is_valid_date(object.get(r, "definedOn", null))
	finding := {
		"severity": "error",
		"rule": "ladder/defined-on-invalid",
		"message": sprintf("ladder rung '%s' must carry definedOn as a real YYYY-MM-DD date — the day this severity was defined", [object.get(r, "name", "unnamed")]),
		"path": sprintf("$.alerting.severityLadder[%d].definedOn", [i]),
	}
}

f_ladder contains finding if {
	some i, r in ladder_rungs
	lib.is_valid_date(object.get(r, "definedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(r, "definedOn", null)) > lib.date_to_days(object.get(input, "today", null))
	finding := {
		"severity": "error",
		"rule": "ladder/defined-in-future",
		"message": sprintf("ladder rung '%s' carries a definedOn date in the future: a severity cannot be defined before it is defined", [object.get(r, "name", null)]),
		"path": sprintf("$.alerting.severityLadder[%d].definedOn", [i]),
	}
}

f_ladder contains finding if {
	names := [object.get(r, "name", null) |
		some r in ladder_rungs
		lib.is_nonempty_string(object.get(r, "name", null))
	]
	some name in names
	count([n | some n in names; n == name]) > 1
	finding := {
		"severity": "error",
		"rule": "ladder/name-duplicate",
		"message": sprintf("severity '%s' appears more than once on the ladder", [name]),
		"path": "$.alerting.severityLadder",
	}
}

# --- findings: runbooks ------------------------------------------------------------

f_runbooks contains finding if {
	is_object(alerting_doc)
	not is_array(object.get(alerting_doc, "runbooks", null))
	finding := {
		"severity": "error",
		"rule": "runbooks/must-be-array",
		"message": "runbooks must be an array of {id, link, escalationClock} entries",
		"path": "$.alerting.runbooks",
	}
}

f_runbooks contains finding if {
	is_object(alerting_doc)
	is_array(object.get(alerting_doc, "runbooks", null))
	count(runbooks) == 0
	finding := {
		"severity": "error",
		"rule": "runbooks/required",
		"message": "the alerting contract must carry at least one runbook: an alert rule that pages must point at what to do",
		"path": "$.alerting.runbooks",
	}
}

f_runbook_content contains finding if {
	some i, r in as_array(alerting_doc, "runbooks")
	not is_object(r)
	finding := {
		"severity": "error",
		"rule": "runbooks/entry-must-be-object",
		"message": sprintf("runbook entry %d must be an object with id, link, and escalationClock", [i]),
		"path": sprintf("$.alerting.runbooks[%d]", [i]),
	}
}

f_runbook_content contains finding if {
	some i, r in runbooks
	not lib.is_nonempty_string(object.get(r, "id", null))
	finding := {
		"severity": "error",
		"rule": "runbook/id-required",
		"message": sprintf("runbook entry %d must carry a non-empty id", [i]),
		"path": sprintf("$.alerting.runbooks[%d].id", [i]),
	}
}

f_runbook_content contains finding if {
	some i, r in runbooks
	lib.is_nonempty_string(object.get(r, "id", null))
	not lib.is_nonempty_string(object.get(r, "link", null))
	finding := {
		"severity": "error",
		"rule": "runbook/link-required",
		"message": sprintf("runbook '%s' must carry a non-empty link: the runbook must be a place you can go", [object.get(r, "id", null)]),
		"path": sprintf("$.alerting.runbooks[%d].link", [i]),
	}
}

# The issue's own words: a runbook that lacks its escalation clock is
# a gate failure, not a style nit. "Who escalates, by when" is part of
# the contract — the clock is what makes a runbook more than a wiki page.
f_runbook_content contains finding if {
	some i, r in runbooks
	lib.is_nonempty_string(object.get(r, "id", null))
	not lib.is_nonempty_string(object.get(r, "escalationClock", null))
	finding := {
		"severity": "error",
		"rule": "runbook/escalation-clock-required",
		"message": sprintf("runbook '%s' must carry its escalation clock: who escalates, by when — a runbook without a clock is a wiki page, not a runbook", [object.get(r, "id", null)]),
		"path": sprintf("$.alerting.runbooks[%d].escalationClock", [i]),
	}
}

f_runbook_content contains finding if {
	ids := [object.get(r, "id", null) |
		some r in runbooks
		lib.is_nonempty_string(object.get(r, "id", null))
	]
	some id in ids
	count([x | some x in ids; x == id]) > 1
	finding := {
		"severity": "error",
		"rule": "runbook/id-duplicate",
		"message": sprintf("runbook '%s' appears more than once in the contract", [id]),
		"path": "$.alerting.runbooks",
	}
}

# --- findings: alert rules ------------------------------------------------------------

f_alerts_array contains finding if {
	is_object(alerting_doc)
	not is_array(object.get(alerting_doc, "alerts", null))
	finding := {
		"severity": "error",
		"rule": "alerts/must-be-array",
		"message": "alerts must be an array of {id, owner, severity, runbook, recordDestination} entries",
		"path": "$.alerting.alerts",
	}
}

f_alerts_array contains finding if {
	is_object(alerting_doc)
	is_array(object.get(alerting_doc, "alerts", null))
	count(alert_rules) == 0
	finding := {
		"severity": "error",
		"rule": "alerts/required",
		"message": "the alerting contract must declare at least one alert rule",
		"path": "$.alerting.alerts",
	}
}

f_alert_content contains finding if {
	some i, a in as_array(alerting_doc, "alerts")
	not is_object(a)
	finding := {
		"severity": "error",
		"rule": "alerts/entry-must-be-object",
		"message": sprintf("alert entry %d must be an object with id, owner, severity, runbook, and recordDestination", [i]),
		"path": sprintf("$.alerting.alerts[%d]", [i]),
	}
}

f_alert_content contains finding if {
	some i, a in alert_rules
	not lib.is_nonempty_string(object.get(a, "id", null))
	finding := {
		"severity": "error",
		"rule": "alert/id-required",
		"message": sprintf("alert entry %d must carry a non-empty id", [i]),
		"path": sprintf("$.alerting.alerts[%d].id", [i]),
	}
}

f_alert_content contains finding if {
	some i, a in alert_rules
	lib.is_nonempty_string(object.get(a, "id", null))
	not lib.is_nonempty_string(object.get(a, "owner", null))
	finding := {
		"severity": "error",
		"rule": "alert/owner-required",
		"message": sprintf("alert rule '%s' must name an owner: a page nobody owns is nobody's page", [object.get(a, "id", null)]),
		"path": sprintf("$.alerting.alerts[%d].owner", [i]),
	}
}

f_alert_content contains finding if {
	some i, a in alert_rules
	lib.is_nonempty_string(object.get(a, "id", null))
	not object.get(a, "severity", null) in ladder_names
	finding := {
		"severity": "error",
		"rule": "alert/severity-unknown",
		"message": sprintf("alert rule '%s' carries severity '%s', which is not on the severity ladder (%s): severities are defined facts, not judgment calls", [
			object.get(a, "id", null),
			object.get(a, "severity", null),
			concat(", ", sort(ladder_names)),
		]),
		"path": sprintf("$.alerting.alerts[%d].severity", [i]),
	}
}

f_alert_content contains finding if {
	some i, a in alert_rules
	lib.is_nonempty_string(object.get(a, "id", null))
	lib.is_nonempty_string(object.get(a, "severity", null))
	ladder_known(object.get(a, "severity", null))
	lib.is_valid_date(rung_defined_on(object.get(a, "severity", null)))
	lib.is_valid_date(object.get(alerting_doc, "reviewedOn", null))
	lib.date_to_days(rung_defined_on(object.get(a, "severity", null))) > lib.date_to_days(object.get(alerting_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "alert/severity-newer-than-review",
		"message": sprintf("alert rule '%s' uses severity '%s', which was defined on the ladder after the contract's own review date: the rule was never reviewed against the ladder it cites", [
			object.get(a, "id", null),
			object.get(a, "severity", null),
		]),
		"path": sprintf("$.alerting.alerts[%d].severity", [i]),
	}
}

f_alert_content contains finding if {
	some i, a in alert_rules
	lib.is_nonempty_string(object.get(a, "id", null))
	not object.get(a, "runbook", null) in runbook_ids
	finding := {
		"severity": "error",
		"rule": "alert/runbook-unknown",
		"message": sprintf("alert rule '%s' points at runbook '%s', which the contract does not declare: an alert that pages must point at what to do", [object.get(a, "id", null), object.get(a, "runbook", null)]),
		"path": sprintf("$.alerting.alerts[%d].runbook", [i]),
	}
}

f_alert_content contains finding if {
	some i, a in alert_rules
	lib.is_nonempty_string(object.get(a, "id", null))
	not lib.is_nonempty_string(object.get(a, "recordDestination", null))
	finding := {
		"severity": "error",
		"rule": "alert/record-destination-required",
		"message": sprintf("alert rule '%s' must name its record destination: nothing pages without creating a record — say where the record goes", [object.get(a, "id", null)]),
		"path": sprintf("$.alerting.alerts[%d].recordDestination", [i]),
	}
}

f_alert_content contains finding if {
	ids := [object.get(a, "id", null) |
		some a in alert_rules
		lib.is_nonempty_string(object.get(a, "id", null))
	]
	some id in ids
	count([x | some x in ids; x == id]) > 1
	finding := {
		"severity": "error",
		"rule": "alert/id-duplicate",
		"message": sprintf("alert rule '%s' appears more than once in the contract", [id]),
		"path": "$.alerting.alerts",
	}
}

# --- findings: runbooks the contract declares but no rule pages from ---------------

# A runbook no alert rule points at is maintenance debt, not a gate
# failure — the ladder and clocks still hold. It warns, honestly.
f_alert_refs contains finding if {
	some r in runbooks
	lib.is_nonempty_string(object.get(r, "id", null))
	not object.get(r, "id", null) in referenced_runbook_ids
	finding := {
		"severity": "warning",
		"rule": "runbook/unreferenced",
		"message": sprintf("runbook '%s' is declared but no alert rule points at it", [object.get(r, "id", null)]),
		"path": sprintf("$.alerting.runbooks[%d]", [runbook_index(object.get(r, "id", null))]),
	}
}

referenced_runbook_ids := {object.get(a, "runbook", null) |
	some a in alert_rules
	lib.is_nonempty_string(object.get(a, "id", null))
}

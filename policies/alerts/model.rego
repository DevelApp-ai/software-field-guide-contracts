# The shared model for the alert-to-record linkage gate — The Software
# Field Guide, issue #69.
#
# Two documents enter: the alerting contract (the severity ladder, the
# runbooks with their escalation clocks, and the alert rules that name
# an owner, a severity, a runbook, and a record destination) and the
# incident register (the alerts that actually fired, the incidents they
# opened, and each incident's postmortem actions). The contract is the
# promise made before anything pages; the register is the evidence of
# what happened after. Every accessor here guards its input before
# touching object fields — a malformed document must produce findings,
# never a WASM trap.
package alerts

import rego.v1

import data.alerts.lib

# --- the input documents ------------------------------------------------------

alerting_doc := v if {
	is_object(input)
	v := object.get(input, "alerting", null)
}

alerting_doc := null if not is_object(input)

register_doc := v if {
	is_object(input)
	v := object.get(input, "register", null)
}

register_doc := null if not is_object(input)

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

# --- the alerting contract: severity ladder ---------------------------------------

ladder_rungs := [r | some r in as_array(alerting_doc, "severityLadder"); is_object(r)]

ladder_names := {object.get(r, "name", null) |
	some r in ladder_rungs
	lib.is_nonempty_string(object.get(r, "name", null))
}

# First rung carrying this name — duplicate names are the validator's
# finding, never an ambiguity for lookups.
ladder_rung(name) := r if {
	matches := [r |
		some r in ladder_rungs
		object.get(r, "name", null) == name
	]
	count(matches) > 0
	r := matches[0]
}

ladder_known(name) if ladder_rung(name)

# The date the severity was defined on the ladder — the fact the gate
# needs to answer "was this severity defined before the incident?"
rung_defined_on(name) := object.get(ladder_rung(name), "definedOn", null)

# The position of a rung (or of a rung name) in the ladder document, so
# a finding can cite the exact rung.
ladder_rung_index(name) := i if {
	matches := [i |
		some i, r in ladder_rungs
		object.get(r, "name", null) == name
	]
	count(matches) > 0
	i := matches[0]
}

# --- the alerting contract: runbooks -----------------------------------------------

runbooks := [r | some r in as_array(alerting_doc, "runbooks"); is_object(r)]

runbook_ids := {object.get(r, "id", null) |
	some r in runbooks
	lib.is_nonempty_string(object.get(r, "id", null))
}

runbook_index(id) := i if {
	matches := [i |
		some i, r in runbooks
		object.get(r, "id", null) == id
	]
	count(matches) > 0
	i := matches[0]
}

# --- the alerting contract: alert rules ----------------------------------------------

alert_rules := [a | some a in as_array(alerting_doc, "alerts"); is_object(a)]

alert_ids := {object.get(a, "id", null) |
	some a in alert_rules
	lib.is_nonempty_string(object.get(a, "id", null))
}

alert_index(id) := i if {
	matches := [i |
		some i, a in alert_rules
		object.get(a, "id", null) == id
	]
	count(matches) > 0
	i := matches[0]
}

# --- the incident register: fired alerts -------------------------------------------------

fired_alerts := [f | some f in as_array(register_doc, "firedAlerts"); is_object(f)]

fired_alert_name(f) := object.get(f, "alert", null)

fired_alert_fired_on(f) := object.get(f, "firedOn", null)

fired_row_well_formed(f) if {
	is_object(f)
	lib.is_nonempty_string(fired_alert_name(f))
	lib.is_valid_date(fired_alert_fired_on(f))
}

# --- the incident register: incidents ------------------------------------------------------

incidents := [i | some i in as_array(register_doc, "incidents"); is_object(i)]

incident_id(i) := object.get(i, "id", null)

incident_detected_on(i) := object.get(i, "detectedOn", null)

incident_severity(i) := object.get(i, "severity", null)

incident_record(i) := object.get(i, "record", null)

incident_alerts(i) := as_array(i, "alerts")

incident_row_well_formed(i) if {
	is_object(i)
	lib.is_nonempty_string(incident_id(i))
	lib.is_valid_date(incident_detected_on(i))
	lib.is_nonempty_string(incident_severity(i))
	lib.is_nonempty_string(incident_record(i))
	is_array(object.get(i, "alerts", []))
	every a in incident_alerts(i) {
		lib.is_nonempty_string(a)
	}
}

# The position of an incident (or of a postmortem action inside it) in
# the register document, so a finding can cite the exact row.
incident_index(id) := n if {
	matches := [n |
		some n, i in incidents
		object.get(i, "id", null) == id
	]
	count(matches) > 0
	n := matches[0]
}

# --- the incident register: postmortem actions ---------------------------------------------

action_id(a) := object.get(a, "id", null)

action_text(a) := object.get(a, "action", null)

action_closed_on(a) := object.get(a, "closedOn", null)

action_verified_by(a) := object.get(a, "verifiedBy", null)

action_row_well_formed(a) if {
	is_object(a)
	lib.is_nonempty_string(action_id(a))
	lib.is_nonempty_string(action_text(a))
}

# Closure verification is the register's proof an action is done: a
# real close date and a named verifier. Either half missing means the
# action is not verified yet — an open item, not a closed one.
action_verified(a) if {
	lib.is_valid_date(action_closed_on(a))
	lib.is_nonempty_string(action_verified_by(a))
}

# --- linkage: which incident claims a fired alert ------------------------------------------

# The alert ids a well-formed incident claims — the linkage side of the
# "nothing pages without creating a record" rule.
claimed_alerts := {a |
	some i in incidents
	incident_row_well_formed(i)
	some a in incident_alerts(i)
}

# The first well-formed incident (in document order) that claims an
# alert — the record the alert's page is linked to.
claiming_incident(alert) := i if {
	matches := [i |
		some i in incidents
		incident_row_well_formed(i)
		alert in incident_alerts(i)
	]
	count(matches) > 0
	i := matches[0]
}

alert_linked(alert) if claiming_incident(alert)

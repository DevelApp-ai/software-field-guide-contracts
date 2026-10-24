# Incident register gate — The Software Field Guide, issue #69.
#
# The chapter's core rule, enforced: nothing pages without creating a
# record. The gate reads the incident register — the alerts that fired
# and the incidents they opened — against the alerting contract, and
# fails loudly when the paper trail is broken: an alert that fired but
# links to no incident record (alerts/no-record-linkage), an incident
# graded with a severity that is not on the ladder at all
# (gate/severity-off-ladder) or was defined on the ladder only after
# the incident was detected (gate/severity-defined-after-detection) —
# the severity was invented during the incident — and a postmortem
# action that lacks closure verification in the register
# (gate/action-unverified). The linkages list renders the decision: each
# fired alert and the record it links to, or the absence of one.
#
# Input (JSON): {"alerting": {...}, "register": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [...], "linkages": [...]}
package alerts

import rego.v1

import data.alerts.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"linkages": linkages,
	}
}

gate_findings := (((((((f_input_invalid | f_alerting_missing) | f_register_missing) | f_register_shape) | f_register_rows) | f_gate_alerts) | f_gate_incidents) | f_gate_actions) | f_register_stamps

# --- findings: the register's own stamps --------------------------------------------

# The register is owned and reviewed like the budget: a trail nobody
# owns and nobody re-reads is a trail that stops being kept.
f_register_stamps contains finding if {
	is_object(register_doc)
	not lib.is_nonempty_string(object.get(register_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "register/owner-required",
		"message": "the incident register must name an owner: a register with an owner and a review cadence is the discipline",
		"path": "$.register.owner",
	}
}

f_register_stamps contains finding if {
	is_object(register_doc)
	not lib.is_valid_date(object.get(register_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "register/reviewed-on-invalid",
		"message": "the incident register must carry reviewedOn as a real YYYY-MM-DD date",
		"path": "$.register.reviewedOn",
	}
}

f_register_stamps contains finding if {
	is_object(register_doc)
	lib.is_valid_date(object.get(register_doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(register_doc, "reviewedOn", null)) > lib.date_to_days(object.get(input, "today", null))
	finding := {
		"severity": "error",
		"rule": "register/reviewed-in-future",
		"message": "the incident register carries a reviewedOn date in the future",
		"path": "$.register.reviewedOn",
	}
}

f_register_stamps contains finding if {
	is_object(register_doc)
	lib.is_valid_date(object.get(register_doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(input, "today", null)) - lib.date_to_days(object.get(register_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "register/reviewed-stale",
		"message": "the incident register was reviewed more than 365 days before today: this document is stale",
		"path": "$.register.reviewedOn",
	}
}

# --- findings: the register must be readable ----------------------------------------

f_register_missing contains finding if {
	is_object(input)
	not is_object(register_doc)
	finding := {
		"severity": "error",
		"rule": "register/missing",
		"message": "the incident register is required: pass it as input.register",
		"path": "$.register",
	}
}

f_register_shape contains finding if {
	is_object(register_doc)
	not is_array(object.get(register_doc, "firedAlerts", null))
	finding := {
		"severity": "error",
		"rule": "register/fired-alerts-must-be-array",
		"message": "firedAlerts must be an array of {alert, firedOn} entries",
		"path": "$.register.firedAlerts",
	}
}

f_register_shape contains finding if {
	is_object(register_doc)
	not is_array(object.get(register_doc, "incidents", null))
	finding := {
		"severity": "error",
		"rule": "register/incidents-must-be-array",
		"message": "incidents must be an array of {id, detectedOn, severity, record, alerts, postmortem} entries",
		"path": "$.register.incidents",
	}
}

f_register_rows contains finding if {
	some i, f in fired_alerts
	not fired_row_well_formed(f)
	finding := {
		"severity": "error",
		"rule": "gate/fired-alert-row-invalid",
		"message": sprintf("fired alert entry %d must carry alert (a non-empty string naming a rule in the contract) and firedOn (a real YYYY-MM-DD date)", [i]),
		"path": sprintf("$.register.firedAlerts[%d]", [i]),
	}
}

f_register_rows contains finding if {
	some i, inc in incidents
	not incident_row_well_formed(inc)
	finding := {
		"severity": "error",
		"rule": "gate/incident-row-invalid",
		"message": sprintf("incident entry %d must carry id, detectedOn (a real date), severity, record (the record this incident lives in), and an alerts array", [i]),
		"path": sprintf("$.register.incidents[%d]", [i]),
	}
}

f_register_rows contains finding if {
	some i, inc in incidents
	incident_row_well_formed(inc)
	some j, a in as_array(inc, "postmortem")
	not action_row_well_formed(a)
	finding := {
		"severity": "error",
		"rule": "gate/action-row-invalid",
		"message": sprintf("postmortem action %d of incident '%s' must carry id and action (non-empty strings)", [j, incident_id(inc)]),
		"path": sprintf("$.register.incidents[%d].postmortem[%d]", [i, j]),
	}
}

# --- findings: the register must speak the contract's language -----------------------

f_gate_alerts contains finding if {
	some i, f in fired_alerts
	fired_row_well_formed(f)
	not fired_alert_name(f) in alert_ids
	finding := {
		"severity": "error",
		"rule": "gate/alert-undeclared",
		"message": sprintf("the register records alert '%s' firing, but the alerting contract does not declare it: the register and the contract disagree", [fired_alert_name(f)]),
		"path": sprintf("$.register.firedAlerts[%d].alert", [i]),
	}
}

f_gate_alerts contains finding if {
	some i, inc in incidents
	incident_row_well_formed(inc)
	some a in incident_alerts(inc)
	not a in alert_ids
	finding := {
		"severity": "error",
		"rule": "gate/alert-undeclared",
		"message": sprintf("incident '%s' claims alert '%s', which the alerting contract does not declare: the register and the contract disagree", [incident_id(inc), a]),
		"path": sprintf("$.register.incidents[%d].alerts", [i]),
	}
}

# --- findings: the page without a record — the issue's core rule --------------------

# A fired alert that no incident claims paged without creating a
# record. The register is the evidence that paging leaves a trail; this
# is the gap in the trail.
f_gate_alerts contains finding if {
	some i, f in fired_alerts
	fired_row_well_formed(f)
	fired_alert_name(f) in alert_ids
	not alert_linked(fired_alert_name(f))
	finding := {
		"severity": "error",
		"rule": "alerts/no-record-linkage",
		"message": sprintf("alert '%s' fired on %s but links to no record in the incident register: nothing pages without creating a record", [
			fired_alert_name(f),
			fired_alert_fired_on(f),
		]),
		"path": sprintf("$.register.firedAlerts[%d]", [i]),
	}
}

# --- findings: severity vs the ladder, at detection time ---------------------------

# Off the ladder entirely: the severity was invented during the
# incident — the register says something the contract never defined.
f_gate_incidents contains finding if {
	some i, inc in incidents
	incident_row_well_formed(inc)
	not incident_severity(inc) in ladder_names
	finding := {
		"severity": "error",
		"rule": "gate/severity-off-ladder",
		"message": sprintf("incident '%s' was graded '%s', which is not on the severity ladder (%s): a severity used during an incident must be a defined fact, not a judgment call made while tired", [
			incident_id(inc),
			incident_severity(inc),
			concat(", ", sort(ladder_names)),
		]),
		"path": sprintf("$.register.incidents[%d].severity", [i]),
	}
}

# On the ladder, but defined only after the incident was detected: at
# detection time this severity did not exist. The issue's own words —
# a severity not on the ladder *defined before the incident*.
f_gate_incidents contains finding if {
	some i, inc in incidents
	incident_row_well_formed(inc)
	ladder_known(incident_severity(inc))
	lib.is_valid_date(rung_defined_on(incident_severity(inc)))
	lib.date_to_days(rung_defined_on(incident_severity(inc))) > lib.date_to_days(incident_detected_on(inc))
	finding := {
		"severity": "error",
		"rule": "gate/severity-defined-after-detection",
		"message": sprintf("incident '%s' was graded '%s' on %s, but that severity was defined on the ladder only on %s: the severity was defined after the incident it grades", [
			incident_id(inc),
			incident_severity(inc),
			incident_detected_on(inc),
			rung_defined_on(incident_severity(inc)),
		]),
		"path": sprintf("$.register.incidents[%d].severity", [i]),
	}
}

# --- findings: postmortem actions must close with verification ----------------------

# A postmortem action without closure verification is a promise, not
# a fix. The register is where closure gets proven: a real close date
# and a named verifier.
f_gate_actions contains finding if {
	some i, inc in incidents
	incident_row_well_formed(inc)
	some j, a in as_array(inc, "postmortem")
	action_row_well_formed(a)
	not action_verified(a)
	finding := {
		"severity": "error",
		"rule": "gate/action-unverified",
		"message": sprintf("postmortem action '%s' of incident '%s' lacks closure verification in the register: it needs a closedOn date and a named verifier — an action without proof of closure is still open", [
			action_id(a),
			incident_id(inc),
		]),
		"path": sprintf("$.register.incidents[%d].postmortem[%d]", [i, j]),
	}
}

# --- linkages: the decision the playground renders -----------------------------------

# Per distinct fired alert, well-formed and declared: the record it
# links to — the claiming incident's record — or null when the page
# created no record. Sorted by alert name; the first claiming incident
# (in document order) wins, deterministically. An alert that fired
# twice is one linkage — the question is whether paging it left a
# record, not how many times it paged.
linkages := sort([{
	"alert": name,
	"record": record_of(name),
} |
	some name in {fired_alert_name(f) |
		some f in fired_alerts
		fired_row_well_formed(f)
	}
	name in alert_ids
])

record_of(alert) := incident_record(claiming_incident(alert)) if alert_linked(alert)

record_of(alert) := null if not alert_linked(alert)

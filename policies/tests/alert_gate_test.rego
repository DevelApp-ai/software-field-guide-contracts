package alerts.gate_test

import rego.v1

import data.alerts

import data.alerts.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_good_register_passes if {
	r := alerts.gate with input as fixture.gate_input(fixture.contract, fixture.register)
	r.valid == true
	count(r.findings) == 0
}

test_linkages_report_one_row_per_distinct_fired_alert if {
	r := alerts.gate with input as fixture.gate_input(fixture.contract, fixture.register)

	# storefront-5xx-rate fired twice; the linkage is one row, linked to
	# the first claiming incident
	count(r.linkages) == 2
	l := [x | some x in r.linkages; x.alert == "storefront-5xx-rate"][0]
	l.record == "INC-2026-038 in the incident register"
	some x in r.linkages
	x.alert == "payment-provider-flap"
	x.record == "INC-2026-043 in the incident register"
}

test_missing_register if {
	r := alerts.gate with input as {"alerting": fixture.contract, "today": fixture.today}
	not r.valid
	error_rules(r)["register/missing"]
}

test_input_must_be_object if {
	r := alerts.gate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_fired_alerts_must_be_array if {
	reg := object.remove(fixture.register, ["firedAlerts"])
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	error_rules(r)["register/fired-alerts-must-be-array"]
}

test_incidents_must_be_array if {
	reg := object.remove(fixture.register, ["incidents"])
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	error_rules(r)["register/incidents-must-be-array"]
}

test_incident_row_invalid if {
	reg := object.union(fixture.register, {"incidents": [
		{"id": "INC-2026-999", "detectedOn": "2026-10-12", "severity": "sev-2"},
	]})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	some f in r.findings
	f.rule == "gate/incident-row-invalid"
	f.path == "$.register.incidents[0]"
}

test_fired_alert_row_invalid if {
	reg := object.union(fixture.register, {"firedAlerts": [
		{"alert": "storefront-5xx-rate", "firedOn": "10-12-2026"},
	]})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	some f in r.findings
	f.rule == "gate/fired-alert-row-invalid"
	f.path == "$.register.firedAlerts[0]"
}

test_undeclared_fired_alert_is_caught if {
	reg := object.union(fixture.register, {"firedAlerts": array.concat(fixture.register.firedAlerts, [
		{"alert": "ghost-alert", "firedOn": "2026-10-15"},
	])})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	some f in r.findings
	f.rule == "gate/alert-undeclared"
	contains(f.message, "the alerting contract does not declare it")
}

test_incident_claiming_undeclared_alert_is_caught if {
	reg := object.union(fixture.register, {"incidents": [
		object.union(fixture.register.incidents[0], {"alerts": ["ghost-alert"]}),
		fixture.register.incidents[1],
		fixture.register.incidents[2],
	]})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	some f in r.findings
	f.rule == "gate/alert-undeclared"
	contains(f.message, "INC-2026-038")
}

# The #69 done-when, verbatim: a seeded unlinked alert caught by
# construction — the register shows the firing, no incident claims it.
test_unlinked_alert_is_caught_by_construction if {
	reg := object.union(fixture.register, {"firedAlerts": array.concat(fixture.register.firedAlerts, [
		{"alert": "storefront-latency", "firedOn": "2026-10-15"},
	])})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	some f in r.findings
	f.rule == "alerts/no-record-linkage"
	contains(f.message, "alert 'storefront-latency' fired on 2026-10-15")
	contains(f.message, "nothing pages without creating a record")
	f.path == "$.register.firedAlerts[3]"

	# and the linkage card renders the absence of the record
	some l in r.linkages
	l.alert == "storefront-latency"
	l.record == null
}

test_severity_off_ladder_is_caught if {
	reg := fixture.with_incident_severity(fixture.register, "INC-2026-043", "sev-0")
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	some f in r.findings
	f.rule == "gate/severity-off-ladder"
	contains(f.message, "INC-2026-043")
	contains(f.message, "'sev-0', which is not on the severity ladder (sev-1, sev-2, sev-3)")
	f.path == "$.register.incidents[2].severity"
}

test_severity_defined_after_detection_is_caught if {
	# sev-1 on the ladder since 2026-06-01 — moved to 2026-10-20, three
	# weeks after INC-2026-038 was graded with it on 2026-09-30
	late := fixture.with_rung_defined_on(fixture.contract, "sev-1", "2026-10-20")
	r := alerts.gate with input as fixture.gate_input(late, fixture.register)
	not r.valid
	some f in r.findings
	f.rule == "gate/severity-defined-after-detection"
	contains(f.message, "graded 'sev-1' on 2026-09-30")
	contains(f.message, "defined on the ladder only on 2026-10-20")
	f.path == "$.register.incidents[0].severity"
}

test_severity_defined_exactly_on_detection_passes if {
	# definedOn == detectedOn: the severity existed when the incident
	# was graded — the ladder is honest
	on_the_day := fixture.with_rung_defined_on(fixture.contract, "sev-1", "2026-09-30")
	r := alerts.gate with input as fixture.gate_input(on_the_day, fixture.register)
	r.valid == true
}

test_postmortem_action_without_closure_verification_is_caught if {
	# act-041-1 closed but no verifier named: a promise, not a fix
	reg := object.union(fixture.register, {"incidents": [
		fixture.register.incidents[0],
		object.union(fixture.register.incidents[1], {"postmortem": [{
			"id": "act-041-1",
			"action": "Gate order_id out of the label schema",
			"closedOn": "2026-10-11",
		}]}),
		fixture.register.incidents[2],
	]})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	some f in r.findings
	f.rule == "gate/action-unverified"
	contains(f.message, "act-041-1")
	contains(f.message, "INC-2026-041")
	f.path == "$.register.incidents[1].postmortem[0]"
}

test_postmortem_action_without_close_date_is_not_verified if {
	reg := object.union(fixture.register, {"incidents": [
		object.union(fixture.register.incidents[0], {"postmortem": [{
			"id": "act-038-1",
			"action": "Remove order_id from the metric labels",
			"verifiedBy": "PR #2141 merged",
		}]}),
		fixture.register.incidents[1],
		fixture.register.incidents[2],
	]})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	error_rules(r)["gate/action-unverified"]
}

test_empty_postmortem_is_not_a_failure if {
	# an open incident with no actions yet is honest — the gate verifies
	# closure of the actions that exist, it does not demand a postmortem
	# on an incident still being worked
	r := alerts.gate with input as fixture.gate_input(fixture.contract, fixture.register)
	r.valid == true
	not error_rules(r)["gate/action-unverified"]
}

test_register_owner_required if {
	reg := object.remove(fixture.register, ["owner"])
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	error_rules(r)["register/owner-required"]
}

test_register_reviewed_on_must_be_a_real_date if {
	reg := object.union(fixture.register, {"reviewedOn": "not-a-date"})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	error_rules(r)["register/reviewed-on-invalid"]
}

test_register_reviewed_in_future if {
	reg := object.union(fixture.register, {"reviewedOn": "2026-12-31"})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	error_rules(r)["register/reviewed-in-future"]
}

test_register_reviewed_stale if {
	# more than 365 days before today (2026-10-20)
	reg := object.union(fixture.register, {"reviewedOn": "2024-01-01"})
	r := alerts.gate with input as fixture.gate_input(fixture.contract, reg)
	not r.valid
	error_rules(r)["register/reviewed-stale"]
}

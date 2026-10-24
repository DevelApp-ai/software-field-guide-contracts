package alerts.policy_test

import rego.v1

import data.alerts

import data.alerts.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

test_valid_contract_passes if {
	r := alerts.validate with input as fixture.validate_input(fixture.contract)
	r.valid == true
	count(r.findings) == 0
}

test_input_must_be_object if {
	r := alerts.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := alerts.validate with input as {"alerting": fixture.contract, "today": "yesterday"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_missing_contract if {
	r := alerts.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["alerting/missing"]
}

test_version_required if {
	c := object.remove(fixture.contract, ["version"])
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["alerting/version-required"]
}

test_reviewed_on_invalid if {
	c := object.union(fixture.contract, {"reviewedOn": "2026-13-01"})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["alerting/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	c := object.union(fixture.contract, {"reviewedOn": "2026-10-21"})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["alerting/reviewed-in-future"]
}

test_reviewed_stale if {
	c := object.union(fixture.contract, {"reviewedOn": "2025-10-19"})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["alerting/reviewed-stale"]
}

test_reviewed_exactly_365_days_old_passes if {
	# a year-old review is fine — but the ladder must be older than the
	# review, or the severities were defined after the last review
	old_ladder := [object.union(r, {"definedOn": "2025-01-01"}) |
		some r in fixture.contract.severityLadder
	]
	c := object.union(fixture.contract, {"reviewedOn": "2025-10-20", "severityLadder": old_ladder})
	r := alerts.validate with input as fixture.validate_input(c)
	r.valid == true
}

test_ladder_must_be_array if {
	c := object.remove(fixture.contract, ["severityLadder"])
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["ladder/must-be-array"]
}

test_ladder_required if {
	c := object.union(fixture.contract, {"severityLadder": []})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["ladder/required"]
}

test_ladder_name_required if {
	c := object.union(fixture.contract, {"severityLadder": [
		{"description": "A rung with no name", "definedOn": "2026-01-15"},
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	some f in r.findings
	f.rule == "ladder/name-required"
	f.path == "$.alerting.severityLadder[0].name"
}

test_ladder_description_required if {
	c := object.union(fixture.contract, {"severityLadder": [
		{"name": "sev-x", "definedOn": "2026-01-15"},
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["ladder/description-required"]
}

test_ladder_defined_on_invalid if {
	c := object.union(fixture.contract, {"severityLadder": [
		{"name": "sev-x", "description": "A rung", "definedOn": "January"},
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["ladder/defined-on-invalid"]
}

test_ladder_defined_in_future if {
	c := object.union(fixture.contract, {"severityLadder": [
		{"name": "sev-x", "description": "A rung", "definedOn": "2026-10-21"},
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["ladder/defined-in-future"]
}

test_ladder_name_duplicate if {
	c := object.union(fixture.contract, {"severityLadder": array.concat(fixture.contract.severityLadder, [
		{"name": "sev-2", "description": "The same rung twice", "definedOn": "2026-01-15"},
	])})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["ladder/name-duplicate"]
}

# The issue's own words: a runbook that lacks its escalation clock
# fails the gate, with the runbook cited.
test_runbook_without_escalation_clock_is_an_error if {
	c := object.union(fixture.contract, {"runbooks": [
		fixture.contract.runbooks[0],
		object.remove(fixture.contract.runbooks[1], ["escalationClock"]),
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	some f in r.findings
	f.rule == "runbook/escalation-clock-required"
	contains(f.message, "rb-payment-provider")
	f.path == "$.alerting.runbooks[1].escalationClock"
}

test_runbook_link_required if {
	c := object.union(fixture.contract, {"runbooks": [
		object.remove(fixture.contract.runbooks[0], ["link"]),
		fixture.contract.runbooks[1],
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["runbook/link-required"]
}

test_runbooks_required if {
	c := object.union(fixture.contract, {"runbooks": []})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["runbooks/required"]
}

test_alert_owner_required if {
	c := object.union(fixture.contract, {"alerts": [
		object.remove(fixture.contract.alerts[0], ["owner"]),
		fixture.contract.alerts[1],
		fixture.contract.alerts[2],
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	some f in r.findings
	f.rule == "alert/owner-required"
	contains(f.message, "storefront-5xx-rate")
	f.path == "$.alerting.alerts[0].owner"
}

test_alert_severity_off_ladder_is_an_error if {
	c := object.union(fixture.contract, {"alerts": [
		object.union(fixture.contract.alerts[0], {"severity": "sev-9"}),
		fixture.contract.alerts[1],
		fixture.contract.alerts[2],
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	some f in r.findings
	f.rule == "alert/severity-unknown"
	contains(f.message, "not on the severity ladder (sev-1, sev-2, sev-3)")
	f.path == "$.alerting.alerts[0].severity"
}

test_alert_severity_newer_than_the_review_is_an_error if {
	# sev-1 was defined on 2026-06-01; move it to 2026-10-18, after the
	# contract's own review — the rule using it was never reviewed
	# against the ladder it cites.
	late := fixture.with_rung_defined_on(fixture.contract, "sev-1", "2026-10-18")
	c := object.union(late, {"alerts": [
		object.union(fixture.contract.alerts[0], {"severity": "sev-1"}),
		fixture.contract.alerts[1],
		fixture.contract.alerts[2],
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	some f in r.findings
	f.rule == "alert/severity-newer-than-review"
	contains(f.message, "storefront-5xx-rate")
}

test_alert_runbook_unknown if {
	c := object.union(fixture.contract, {"alerts": [
		object.union(fixture.contract.alerts[0], {"runbook": "rb-ghost"}),
		fixture.contract.alerts[1],
		fixture.contract.alerts[2],
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	some f in r.findings
	f.rule == "alert/runbook-unknown"
	contains(f.message, "rb-ghost")
	f.path == "$.alerting.alerts[0].runbook"
}

test_alert_record_destination_required if {
	c := object.union(fixture.contract, {"alerts": [
		object.remove(fixture.contract.alerts[0], ["recordDestination"]),
		fixture.contract.alerts[1],
		fixture.contract.alerts[2],
	]})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	some f in r.findings
	f.rule == "alert/record-destination-required"
	contains(f.message, "nothing pages without creating a record")
	f.path == "$.alerting.alerts[0].recordDestination"
}

test_alert_id_duplicate if {
	c := object.union(fixture.contract, {"alerts": array.concat(fixture.contract.alerts, [
		object.union(fixture.contract.alerts[0], {"owner": "Someone else"}),
	])})
	r := alerts.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["alert/id-duplicate"]
}

test_unreferenced_runbook_is_a_warning if {
	# a runbook no alert rule points at is maintenance debt, not a gate
	# failure — the ladder and clocks still hold, so it stays valid
	c := object.union(fixture.contract, {"runbooks": array.concat(fixture.contract.runbooks, [{
		"id": "rb-legacy-queue",
		"link": "https://example/runbooks/legacy-queue.md",
		"escalationClock": "Acknowledge in 30 minutes",
	}])})
	r := alerts.validate with input as fixture.validate_input(c)
	r.valid == true
	warning_rules(r)["runbook/unreferenced"]
}

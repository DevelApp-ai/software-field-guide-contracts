package ingress.gate_test

import rego.v1

import data.ingress

import data.ingress.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

card(r, area, item) := c if {
	some c in r.cards
	c.area == area
	c.item == item
}

# --- the control: one rehearsed platform, everything hardened -------------------

test_control_gate_passes_and_renders_hardened if {
	r := ingress.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "hardened"
}

test_control_renders_ten_cards_in_fixed_area_order if {
	r := ingress.gate with input as fixture.control_input
	count(r.cards) == 10
	r.cards[0].area == "request policy"
	r.cards[1].area == "allowed domains"
	r.cards[2].area == "allowed domains"
	r.cards[3].area == "tls certificates"
	r.cards[4].area == "tls certificates"
	r.cards[5].area == "service level objectives"
	r.cards[6].area == "audit coverage"
	r.cards[7].area == "audit coverage"
	r.cards[8].area == "audit coverage"
	r.cards[9].area == "kill path"
}

test_control_cards_are_sorted_inside_each_area if {
	r := ingress.gate with input as fixture.control_input
	r.cards[1].item == "partner.example.com"
	r.cards[2].item == "*.dev.internal"
	r.cards[6].item == "developer-app"
	r.cards[7].item == "health-check"
	r.cards[8].item == "partner-api"
}

test_control_card_verdicts_are_all_hardened if {
	r := ingress.gate with input as fixture.control_input
	count([c | some c in r.cards; c.verdict == "hardened"]) == 10
}

test_control_card_details if {
	r := ingress.gate with input as fixture.control_input
	card(r, "request policy", "default-deny").detail == "default-deny declared: the edge rejects by default and admits by exception (ingress-case.yaml)"
	card(r, "allowed domains", "*.dev.internal").detail == "wildcard granted for 'dev.internal', contained inside the platform zone 'dev.internal' (ingress-case.yaml)"
	card(r, "kill path", "seal-edge").detail == "rehearsed on 2026-10-10, inside the drill record's 180-day staleness clock (drill.yaml)"
}

test_gate_answers_in_the_stable_shape if {
	r := ingress.gate with input as fixture.control_input
	object.keys(r) == {"cards", "findings", "valid", "verdict"}
}

test_gate_input_must_be_object if {
	r := ingress.gate with input as [1, 2]
	not r.valid
	r.verdict == "exposed"
}

test_gate_case_missing if {
	r := ingress.gate with input as {"drill": fixture.drill, "today": fixture.today}
	not r.valid
	error_rules(r)["case/missing"]
}

# --- the drill record's own stamps ----------------------------------------------

test_drill_version_required if {
	d := fixture.with_field(fixture.drill, {"version": null})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drill/version-required"]
}

test_drill_reviewed_on_invalid if {
	d := fixture.with_field(fixture.drill, {"reviewedOn": "15/10/2026"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drill/reviewed-on-invalid"]
}

test_drill_reviewed_in_future if {
	d := fixture.with_field(fixture.drill, {"reviewedOn": "2026-12-01"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drill/reviewed-in-future"]
}

test_drill_owner_required if {
	d := fixture.with_field(fixture.drill, {"owner": ""})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drill/owner-required"]
}

# --- the rehearsal rows ----------------------------------------------------------

test_drills_must_be_array if {
	d := fixture.with_field(fixture.drill, {"drills": "seal-edge"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drills/must-be-array"]
}

test_drill_row_must_be_object if {
	d := fixture.with_field(fixture.drill, {"drills": ["seal-edge"]})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drills/row-must-be-object"]
}

test_drill_killpath_required if {
	d := fixture.with_drill_row_field(fixture.drill, "seal-edge", {"killPath": null})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drill/killpath-required"]
}

test_drill_drilled_on_required if {
	d := fixture.with_drill_row_field(fixture.drill, "seal-edge", {"drilledOn": "10/10/2026"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drill/drilled-on-required"]
}

test_drill_evidence_required if {
	d := fixture.with_drill_row_field(fixture.drill, "seal-edge", {"evidence": ""})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drill/evidence-required"]
}

test_drill_future_dated if {
	d := fixture.with_drill_row_field(fixture.drill, "seal-edge", {"drilledOn": "2026-12-01"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drill/future-dated"]
}

# --- the case × drill join --------------------------------------------------------

test_drill_rehearses_unknown_killpath if {
	d := fixture.with_drill_row_field(fixture.drill, "seal-edge", {"killPath": "drain-pipes"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	error_rules(r)["drill/killpath-unknown"]
}

# --- the kill path's rehearsal clock ----------------------------------------------

test_never_rehearsed_without_a_drill_record if {
	r := ingress.gate with input as object.remove(fixture.control_input, {"drill"})
	not r.valid
	r.verdict == "exposed"
	error_rules(r)["killpath/never-rehearsed"]
}

test_never_rehearsed_with_an_empty_drill_record if {
	d := fixture.with_field(fixture.drill, {"drills": []})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	not r.valid
	r.verdict == "exposed"
	error_rules(r)["killpath/never-rehearsed"]
	card(r, "kill path", "seal-edge").verdict == "exposed"
}

test_never_rehearsed_bites_exactly_once if {
	d := fixture.with_field(fixture.drill, {"drills": []})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	count([f | some f in r.findings; f.rule == "killpath/never-rehearsed"]) == 1
}

test_future_dated_rehearsal_never_softens_the_posture if {
	# A drill dated in the future is its own error and never counts
	# as the rehearsal the kill path needs.
	d := fixture.with_drill_row_field(fixture.drill, "seal-edge", {"drilledOn": "2026-12-01"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	error_rules(r)["drill/future-dated"]
	error_rules(r)["killpath/never-rehearsed"]
}

test_stale_rehearsal_flags_honestly if {
	d := fixture.with_drill_row_field(fixture.drill, "seal-edge", {"drilledOn": "2026-02-10"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	r.valid == true
	r.verdict == "review"
	warning_rules(r)["killpath/stale-rehearsal"]
	not error_rules(r)["killpath/stale-rehearsal"]
	card(r, "kill path", "seal-edge").verdict == "review"
}

test_rehearsal_on_the_staleness_boundary_is_fresh if {
	# 2026-04-23 is exactly 180 days before the anchor date: the
	# boundary itself is inside the clock, not beyond it.
	d := fixture.with_drill_row_field(fixture.drill, "seal-edge", {"drilledOn": "2026-04-23"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	r.valid == true
	r.verdict == "hardened"
	not warning_rules(r)["killpath/stale-rehearsal"]
}

test_staleness_clock_defaults_to_180_days if {
	d := object.remove(fixture.drill, {"maxStalenessDays"})
	r := ingress.gate with input as fixture.gate_input(fixture.case, d)
	r.valid == true
	r.verdict == "hardened"
}

# The gate does not re-judge the case's own content — that is the
# validator's job — but the board still renders the verdict: a
# missing default-deny leaves the gate itself clean while the
# request-policy card says exposed.
test_missing_default_deny_renders_the_request_policy_card_exposed if {
	c := fixture.with_field(fixture.case, {"requestPolicy": {"defaultDeny": false, "decision": "admit everything"}})
	r := ingress.gate with input as fixture.gate_input(c, fixture.drill)
	r.valid == true
	card(r, "request policy", "default-deny").verdict == "exposed"
	card(r, "request policy", "default-deny").detail == "no default-deny: every request rides an allow list that is not an allow list (ingress-case.yaml)"
}

test_unlogged_route_class_renders_the_audit_card_review if {
	c := fixture.with_field(fixture.case, {"loggedRouteClasses": ["developer-app", "health-check"]})
	r := ingress.gate with input as fixture.gate_input(c, fixture.drill)

	# The audit gap is a case finding; the gate still renders the
	# board, and the partner-api card says review.
	card(r, "audit coverage", "partner-api").verdict == "review"
}

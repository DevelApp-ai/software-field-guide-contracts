package compliance.gate_test

import rego.v1

import data.compliance

import data.compliance.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

card(r, req) := c if {
	some c in r.requirements
	c.requirement == req
}

# --- the control: one catalog, four controls, everything mapped ------------------

test_control_gate_passes_and_renders_consistent if {
	r := compliance.gate with input as fixture.control_input
	r.valid == true
	count(r.findings) == 0
	r.verdict == "consistent"
}

test_control_renders_one_card_per_declared_requirement if {
	r := compliance.gate with input as fixture.control_input
	count(r.requirements) == 4
	{c.requirement | some c in r.requirements} == {"PCI-DSS-2.2.7", "PCI-DSS-3.4.1", "SOC2-CC6.1", "GDPR-ART-17"}
}

test_control_cards_are_sorted_by_requirement_id if {
	r := compliance.gate with input as fixture.control_input
	r.requirements[0].requirement == "GDPR-ART-17"
	r.requirements[1].requirement == "PCI-DSS-2.2.7"
	r.requirements[2].requirement == "PCI-DSS-3.4.1"
	r.requirements[3].requirement == "SOC2-CC6.1"
}

test_control_card_verdicts_are_all_consistent if {
	r := compliance.gate with input as fixture.control_input
	count([c | some c in r.requirements; c.verdict == "consistent"]) == 4
}

test_control_card_detail_names_what_covers_it if {
	r := compliance.gate with input as fixture.control_input
	card(r, "PCI-DSS-2.2.7").detail == "covered by control 'CTRL-01' with live evidence 'edge-firewall-review' and a fresh 180-day review clock (controls.yaml, requirements.yaml)"
}

test_gate_answers_in_the_stable_shape if {
	r := compliance.gate with input as fixture.control_input
	object.keys(r) == {"findings", "requirements", "valid", "verdict"}
}

test_gate_input_must_be_object if {
	r := compliance.gate with input as [1, 2]
	not r.valid
	r.verdict == "unreadable"
}

test_controls_missing_fails_the_gate if {
	r := compliance.gate with input as {"requirements": fixture.requirements_catalog, "today": fixture.today}
	not r.valid
	error_rules(r)["controls/missing"]
	r.verdict == "unreadable"
}

# --- the drift: a requirement nobody controls ------------------------------------

test_unmapped_requirement_fails_the_gate if {
	catalog := fixture.with_requirement(fixture.requirements_catalog, {"id": "ISO-27001-A.5.1", "title": "Access rights are subject to an access control policy", "source": "ISO/IEC 27001 A.5.1"})
	r := compliance.gate with input as fixture.gate_input(fixture.controls_manifest, catalog)
	not r.valid
	error_rules(r)["gate/requirement-unmapped"]
	r.verdict == "drifts"
}

test_unmapped_requirement_bites_exactly_once_citing_both_files if {
	catalog := fixture.with_requirement(fixture.requirements_catalog, {"id": "ISO-27001-A.5.1", "title": "Access rights are subject to an access control policy", "source": "ISO/IEC 27001 A.5.1"})
	r := compliance.gate with input as fixture.gate_input(fixture.controls_manifest, catalog)
	count([f | some f in r.findings; f.rule == "gate/requirement-unmapped"]) == 1
	some f in r.findings
	f.rule == "gate/requirement-unmapped"
	contains(f.message, "ISO-27001-A.5.1")
	contains(f.message, "a requirement nobody controls is a promise nobody keeps")
	contains(f.message, "requirements.yaml")
	contains(f.message, "controls.yaml")
}

test_unmapped_requirement_card_names_the_gap if {
	catalog := fixture.with_requirement(fixture.requirements_catalog, {"id": "ISO-27001-A.5.1", "title": "Access rights are subject to an access control policy", "source": "ISO/IEC 27001 A.5.1"})
	r := compliance.gate with input as fixture.gate_input(fixture.controls_manifest, catalog)
	card(r, "ISO-27001-A.5.1").verdict == "drifts"
	card(r, "ISO-27001-A.5.1").detail == "no control maps to it: coverage claimed and never delivered (requirements.yaml, controls.yaml)"
	card(r, "PCI-DSS-2.2.7").verdict == "consistent"
}

# a control removed leaves its requirement uncovered — the same
# drift, arrived at from the manifest's side
test_control_removed_leaves_its_requirement_unmapped if {
	m := fixture.without_control(fixture.controls_manifest, "CTRL-03")
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	not r.valid
	error_rules(r)["gate/requirement-unmapped"]
	card(r, "SOC2-CC6.1").verdict == "drifts"
}

# --- the drift: a control citing a requirement nobody wrote --------------------------

test_requirement_unknown_fails_the_gate if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-03", {"requirements": ["SOC2-CC6.1", "SOC2-CC6.9"]})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	not r.valid
	error_rules(r)["gate/requirement-unknown"]
	r.verdict == "drifts"
}

test_requirement_unknown_bites_exactly_once if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-03", {"requirements": ["SOC2-CC6.1", "SOC2-CC6.9"]})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	count([f | some f in r.findings; f.rule == "gate/requirement-unknown"]) == 1
	some f in r.findings
	f.rule == "gate/requirement-unknown"
	contains(f.message, "CTRL-03")
	contains(f.message, "SOC2-CC6.9")
	contains(f.message, "a requirement nobody wrote")
}

# --- the drift: dead evidence ---------------------------------------------------------

test_retired_evidence_source_fails_the_gate if {
	m := fixture.with_source_field(fixture.controls_manifest, "encryption-config-scan", {"status": "retired"})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	not r.valid
	error_rules(r)["gate/evidence-dead"]
	r.verdict == "drifts"
}

test_retired_evidence_bites_exactly_once_citing_the_control if {
	m := fixture.with_source_field(fixture.controls_manifest, "encryption-config-scan", {"status": "retired"})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	count([f | some f in r.findings; f.rule == "gate/evidence-dead"]) == 1
	some f in r.findings
	f.rule == "gate/evidence-dead"
	contains(f.message, "CTRL-02")
	contains(f.message, "encryption-config-scan")
	contains(f.message, "a control nobody can audit")
	f.path == "$.controls.controls[1].evidenceSource"
}

# A control citing a source the manifest never declared is a
# validation finding, not a drift: the join refuses to run on a
# citation that resolves nowhere.
test_evidence_source_unknown_at_the_gate_is_unreadable if {
	m := fixture.without_source(fixture.controls_manifest, "edge-access-logs")
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	not r.valid
	error_rules(r)["control/evidence-source-unknown"]
	r.verdict == "unreadable"
}

test_dead_evidence_card_names_the_retired_source if {
	m := fixture.with_source_field(fixture.controls_manifest, "encryption-config-scan", {"status": "retired"})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	card(r, "PCI-DSS-3.4.1").verdict == "drifts"
	card(r, "PCI-DSS-3.4.1").detail == "mapped by control 'CTRL-02' but its evidence is dead: the source 'encryption-config-scan' is retired (controls.yaml)"
	card(r, "PCI-DSS-2.2.7").verdict == "consistent"
}

# --- the drift: the lapsed review clock ----------------------------------------------

test_review_clock_expired_fails_the_gate if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-04", {"reviewedOn": "2026-08-15", "intervalDays": 30})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	not r.valid
	error_rules(r)["gate/review-expired"]
	r.verdict == "drifts"
}

test_review_clock_expired_bites_exactly_once_citing_the_clock if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-04", {"reviewedOn": "2026-08-15", "intervalDays": 30})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	count([f | some f in r.findings; f.rule == "gate/review-expired"]) == 1
	some f in r.findings
	f.rule == "gate/review-expired"
	contains(f.message, "CTRL-04")
	contains(f.message, "2026-08-15")
	contains(f.message, "30-day")
	contains(f.message, "a control nobody re-reviews is a control nobody operates")
}

test_review_clock_on_the_boundary_day_is_fresh if {
	# 2026-04-23 is exactly 180 days before the anchor date: due
	# today, and the boundary itself is inside the clock.
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-04", {"reviewedOn": "2026-04-23", "intervalDays": 180})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	r.valid == true
	r.verdict == "consistent"
}

test_expired_clock_card_names_the_lapse if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-04", {"reviewedOn": "2026-08-15", "intervalDays": 30})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	card(r, "GDPR-ART-17").verdict == "drifts"
	card(r, "GDPR-ART-17").detail == "mapped by control 'CTRL-04' but its review clock lapsed: last reviewed 2026-08-15 on a 30-day clock (controls.yaml)"
}

# --- the requirements catalog at the gate ----------------------------------------------

test_requirements_missing_fails_the_gate if {
	r := compliance.gate with input as object.remove(fixture.control_input, {"requirements"})
	not r.valid
	error_rules(r)["requirements/missing"]
	r.verdict == "unreadable"
}

test_requirements_must_be_array if {
	catalog := fixture.with_field(fixture.requirements_catalog, {"requirements": "PCI-DSS-2.2.7"})
	r := compliance.gate with input as fixture.gate_input(fixture.controls_manifest, catalog)
	not r.valid
	error_rules(r)["requirements/must-be-array"]
}

test_requirements_required if {
	catalog := fixture.with_field(fixture.requirements_catalog, {"requirements": []})
	r := compliance.gate with input as fixture.gate_input(fixture.controls_manifest, catalog)
	not r.valid
	some f in r.findings
	f.rule == "requirements/required"
	contains(f.message, "claims the estate must satisfy nothing")
}

test_requirement_row_must_be_object if {
	catalog := fixture.with_field(fixture.requirements_catalog, {"requirements": array.concat(["PCI-DSS-2.2.7"], fixture.requirements_catalog.requirements)})
	r := compliance.gate with input as fixture.gate_input(fixture.controls_manifest, catalog)
	not r.valid
	error_rules(r)["requirements/row-must-be-object"]
}

test_requirement_id_required if {
	catalog := fixture.with_requirement_field(fixture.requirements_catalog, "GDPR-ART-17", {"id": ""})
	r := compliance.gate with input as fixture.gate_input(fixture.controls_manifest, catalog)
	not r.valid
	error_rules(r)["requirement/id-required"]
}

# --- the gate re-reports the manifest's own findings ------------------------------------

test_gate_fails_on_a_stale_manifest if {
	m := fixture.with_field(fixture.controls_manifest, {"reviewedOn": "2024-10-01"})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	not r.valid
	error_rules(r)["controls/reviewed-stale"]
	r.verdict == "unreadable"
}

test_gate_fails_on_a_control_without_evidence if {
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-02", {"evidenceSource": ""})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	not r.valid
	error_rules(r)["control/evidence-required"]
	r.verdict == "unreadable"
}

# The board renders only when the join can be asked at all: with no
# requirements catalog there is nothing to map onto, so no card
# pretends the requirements were covered.
test_cards_render_only_when_the_join_can_be_asked if {
	r := compliance.gate with input as object.remove(fixture.control_input, {"requirements"})
	count(r.requirements) == 0
	r.verdict == "unreadable"
}

test_malformed_catalog_rows_render_no_cards if {
	catalog := fixture.with_field(fixture.requirements_catalog, {"requirements": array.concat([{"title": "a row nobody can cite"}], fixture.requirements_catalog.requirements)})
	r := compliance.gate with input as fixture.gate_input(fixture.controls_manifest, catalog)
	not r.valid
	r.verdict == "unreadable"
	count(r.requirements) == 0
}

# --- the verdict ladder ----------------------------------------------------------------

test_verdict_unreadable_on_document_findings if {
	m := fixture.with_field(fixture.controls_manifest, {"owner": ""})
	r := compliance.gate with input as fixture.gate_input(m, fixture.requirements_catalog)
	r.verdict == "unreadable"
}

test_verdict_drifts_on_join_findings_only if {
	catalog := fixture.with_requirement(fixture.requirements_catalog, {"id": "ISO-27001-A.5.1", "title": "Access rights are subject to an access control policy", "source": "ISO/IEC 27001 A.5.1"})
	r := compliance.gate with input as fixture.gate_input(fixture.controls_manifest, catalog)
	r.verdict == "drifts"
}

test_verdict_drifts_when_two_kinds_of_drift_stack if {
	catalog := fixture.with_requirement(fixture.requirements_catalog, {"id": "ISO-27001-A.5.1", "title": "Access rights are subject to an access control policy", "source": "ISO/IEC 27001 A.5.1"})
	m := fixture.with_control_field(fixture.controls_manifest, "CTRL-04", {"reviewedOn": "2026-08-15", "intervalDays": 30})
	r := compliance.gate with input as fixture.gate_input(m, catalog)
	not r.valid
	error_rules(r)["gate/requirement-unmapped"]
	error_rules(r)["gate/review-expired"]
	r.verdict == "drifts"
}

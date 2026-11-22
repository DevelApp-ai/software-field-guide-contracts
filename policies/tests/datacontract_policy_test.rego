package datacontract.policy_test

import rego.v1

import data.datacontract

import data.datacontract.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_control_contract_valid if {
	r := datacontract.validate with input as fixture.validate_input(fixture.contract)
	r.valid == true
	count(r.findings) == 0
}

test_input_must_be_object if {
	r := datacontract.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := datacontract.validate with input as {"contract": fixture.contract, "today": "2026-13-01"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_contract_missing if {
	r := datacontract.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["contract/missing"]
}

# The unversioned contract: the issue's named broken variant. A
# contract nobody can pin a change against is a prose document with
# delusions.
test_version_required if {
	c := fixture.with_field(fixture.contract, {"version": null})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/version-required"]
}

test_reviewed_on_invalid if {
	c := fixture.with_field(fixture.contract, {"reviewedOn": "18/10/2026"})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	c := fixture.with_field(fixture.contract, {"reviewedOn": "2026-12-01"})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/reviewed-in-future"]
}

test_reviewed_stale if {
	c := fixture.with_field(fixture.contract, {"reviewedOn": "2024-10-01"})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/reviewed-stale"]
}

test_owner_required if {
	c := fixture.with_field(fixture.contract, {"owner": ""})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["contract/owner-required"]
}

test_dataset_required if {
	c := fixture.with_field(fixture.contract, {"dataset": ""})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["dataset/required"]
}

# --- the schema clause --------------------------------------------------------

test_schema_required if {
	c := fixture.with_field(fixture.contract, {"schema": null})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["schema/required"]
}

test_schema_ref_required if {
	c := fixture.with_field(fixture.contract, {"schema": {"ref": "", "subject": "one settlement record as captured by the provider webhook"}})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["schema/ref-required"]
}

test_schema_subject_required if {
	c := fixture.with_field(fixture.contract, {"schema": {"ref": "schemas/settlement-record.schema.json", "subject": ""}})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["schema/subject-required"]
}

# --- the freshness clause -------------------------------------------------------

# The freshness clause without an SLA: the issue's named broken
# variant. A promise of freshness with no number to breach.
test_freshness_sla_required if {
	c := fixture.with_field(fixture.contract, {"freshness": {}})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["freshness/sla-required"]
}

test_freshness_required if {
	c := fixture.with_field(fixture.contract, {"freshness": null})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["freshness/required"]
}

test_freshness_sla_invalid if {
	c := fixture.with_field(fixture.contract, {"freshness": {"slaHours": 0}})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["freshness/sla-invalid"]
}

test_freshness_sla_must_be_a_number if {
	c := fixture.with_field(fixture.contract, {"freshness": {"slaHours": "24"}})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["freshness/sla-invalid"]
}

# --- the quality thresholds ------------------------------------------------------

test_quality_required if {
	c := fixture.with_field(fixture.contract, {"quality": "settlement.completeness"})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["quality/required"]
}

test_quality_threshold_required if {
	c := fixture.with_field(fixture.contract, {"quality": []})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["quality/threshold-required"]
}

test_quality_row_must_be_object if {
	c := fixture.with_field(fixture.contract, {"quality": array.concat(fixture.contract.quality, ["settlement.completeness"])})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["quality/row-must-be-object"]
}

test_quality_metric_required if {
	c := fixture.with_quality_field(fixture.contract, "settlement.completeness", {"metric": ""})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["quality/metric-required"]
}

test_quality_bound_required if {
	c := fixture.with_quality_field(fixture.contract, "settlement.completeness", {"min": null})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["quality/bound-required"]
}

test_quality_bound_ambiguous if {
	c := fixture.with_quality_field(fixture.contract, "settlement.completeness", {"max": 1.0})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["quality/bound-ambiguous"]
}

test_quality_bound_invalid if {
	c := fixture.with_quality_field(fixture.contract, "settlement.completeness", {"min": "99 percent"})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["quality/bound-invalid"]
}

test_quality_duplicate if {
	c := fixture.with_field(fixture.contract, {"quality": array.concat(fixture.contract.quality, [{"metric": "settlement.completeness", "max": 0.9}])})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["quality/duplicate"]
}

# --- the consumers ------------------------------------------------------------

test_consumers_required if {
	c := fixture.with_field(fixture.contract, {"consumers": null})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["consumers/required"]
}

test_consumers_must_be_named if {
	c := fixture.with_field(fixture.contract, {"consumers": []})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["consumers/required"]
}

test_consumer_row_must_be_object if {
	c := fixture.with_field(fixture.contract, {"consumers": array.concat(fixture.contract.consumers, ["Billing team"])})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["consumers/row-must-be-object"]
}

test_consumer_name_required if {
	c := fixture.with_consumer_field(fixture.contract, "Billing team", {"name": ""})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["consumer/name-required"]
}

test_consumer_use_required if {
	c := fixture.with_consumer_field(fixture.contract, "Billing team", {"use": ""})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["consumer/use-required"]
}

test_consumer_duplicate if {
	c := fixture.with_field(fixture.contract, {"consumers": array.concat(fixture.contract.consumers, [{"name": "Billing team", "use": "duplicate"}])})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["consumer/duplicate"]
}

# --- the checks that enforce the contract in CI ----------------------------------

# The contract without enforcement evidence: the issue's named
# broken variant. A promise nobody keeps.
test_enforcement_required if {
	c := fixture.with_field(fixture.contract, {"enforcement": null})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["enforcement/required"]
}

test_enforcement_check_required if {
	c := fixture.with_field(fixture.contract, {"enforcement": []})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["enforcement/check-required"]
}

test_enforcement_row_must_be_object if {
	c := fixture.with_field(fixture.contract, {"enforcement": array.concat(fixture.contract.enforcement, ["schema-conformance"])})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["enforcement/row-must-be-object"]
}

test_check_name_required if {
	c := fixture.with_check_field(fixture.contract, "schema-conformance", {"check": ""})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["check/name-required"]
}

test_check_pipeline_required if {
	c := fixture.with_check_field(fixture.contract, "schema-conformance", {"pipeline": ""})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["check/pipeline-required"]
}

test_check_duplicate if {
	c := fixture.with_field(fixture.contract, {"enforcement": array.concat(fixture.contract.enforcement, [{"check": "schema-conformance", "pipeline": ".github/workflows/data-contract-checks.yaml"}])})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["check/duplicate"]
}

# --- the changes clause -----------------------------------------------------------

test_changes_required if {
	c := fixture.with_field(fixture.contract, {"changes": null})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["changes/required"]
}

test_methodology_required if {
	c := fixture.with_field(fixture.contract, {"changes": {"methodology": "", "deprecationWindowDays": 90}})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["changes/methodology-required"]
}

test_methodology_unknown if {
	c := fixture.with_field(fixture.contract, {"changes": {"methodology": "big-bang-rewrite", "deprecationWindowDays": 90}})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["changes/methodology-unknown"]
}

test_deprecation_window_required if {
	c := fixture.with_field(fixture.contract, {"changes": {"methodology": "expand-migrate-contract", "deprecationWindowDays": null}})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["changes/deprecation-window-required"]
}

test_deprecation_window_invalid if {
	c := fixture.with_field(fixture.contract, {"changes": {"methodology": "expand-migrate-contract", "deprecationWindowDays": 0}})
	r := datacontract.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["changes/deprecation-window-invalid"]
}

# --- lib parity: the date helpers are a verbatim copy of the estate lib ------

test_epoch_is_day_zero if {
	datacontract.lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	datacontract.lib.date_to_days("2026-10-20") - datacontract.lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not datacontract.lib.is_valid_date("2026-02-30")
}

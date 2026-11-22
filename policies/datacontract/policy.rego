# The data contract validated alone — The Software Field Guide,
# issue #106.
#
# Every finding below judges ONE document: the data contract, the
# dataset's promises as data. The enforceable-data-contracts
# chapter's five questions must all have answers — which schema
# binds the data, how fresh it stays, how good its quality
# thresholds are, who owns it, and how it changes — and the answers
# must be checkable: the checks that enforce the contract in CI are
# themselves a clause, named, on the contract. The validator is
# honest about what it models: it checks the contract's own
# completeness — every clause present, internally consistent, and
# datable — not that enforcement actually ran while CI was trusted,
# and not that the schema matches the data. The joins live in the
# gate: evidence for a dataset the contract never names, a declared
# check the enforcement record never shows running, and evidence for
# a check the contract never declared are all judged where the
# contract meets the record.
package datacontract

import rego.v1

import data.datacontract.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_findings := (((((((((f_input_invalid | f_today_invalid) | f_contract_missing) | f_contract_stamps) | f_dataset_name) | f_schema) | f_freshness) | f_quality) | f_consumers) | f_enforcement) | f_changes

# --- findings: the input and the clock -----------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the data contract as input.contract",
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

# --- findings: the contract document and its house stamps -------------------------

f_contract_missing contains finding if {
	not is_object(contract_doc)
	finding := {
		"severity": "error",
		"rule": "contract/missing",
		"message": "the data contract is required: pass it as input.contract",
		"path": "$.contract",
	}
}

f_contract_stamps contains finding if {
	is_object(contract_doc)
	not is_positive_integer(contract_version)
	finding := {
		"severity": "error",
		"rule": "contract/version-required",
		"message": sprintf("the data contract must carry a version (a positive integer): an unversioned contract is a contract nobody can pin a change against (%s)", [contract_file]),
		"path": "$.contract.version",
	}
}

f_contract_stamps contains finding if {
	is_object(contract_doc)
	not lib.is_valid_date(contract_reviewed_on)
	finding := {
		"severity": "error",
		"rule": "contract/reviewed-on-invalid",
		"message": sprintf("the data contract must carry reviewedOn as a real YYYY-MM-DD date (%s)", [contract_file]),
		"path": "$.contract.reviewedOn",
	}
}

f_contract_stamps contains finding if {
	is_object(contract_doc)
	lib.is_valid_date(contract_reviewed_on)
	lib.is_valid_date(today_date)
	lib.date_to_days(contract_reviewed_on) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "contract/reviewed-in-future",
		"message": sprintf("the data contract carries a reviewedOn date in the future (%s)", [contract_file]),
		"path": "$.contract.reviewedOn",
	}
}

f_contract_stamps contains finding if {
	is_object(contract_doc)
	lib.is_valid_date(contract_reviewed_on)
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(contract_reviewed_on) > 365
	finding := {
		"severity": "error",
		"rule": "contract/reviewed-stale",
		"message": sprintf("the data contract was reviewed more than 365 days before today: the dataset changed since, and this document says nothing about it (%s)", [contract_file]),
		"path": "$.contract.reviewedOn",
	}
}

f_contract_stamps contains finding if {
	is_object(contract_doc)
	not lib.is_nonempty_string(contract_owner)
	finding := {
		"severity": "error",
		"rule": "contract/owner-required",
		"message": sprintf("the data contract must name an owner: a contract with an owner and a review cadence is the discipline (%s)", [contract_file]),
		"path": "$.contract.owner",
	}
}

# --- findings: the dataset the contract governs ------------------------------------

f_dataset_name contains finding if {
	is_object(contract_doc)
	not lib.is_nonempty_string(dataset_name)
	finding := {
		"severity": "error",
		"rule": "dataset/required",
		"message": sprintf("the data contract must name the dataset it governs: the enforcement record answers for that dataset and no other (%s)", [contract_file]),
		"path": "$.contract.dataset",
	}
}

# --- findings: the schema clause -----------------------------------------------------

f_schema contains finding if {
	is_object(contract_doc)
	not is_object(object.get(contract_doc, "schema", null))
	finding := {
		"severity": "error",
		"rule": "schema/required",
		"message": sprintf("the data contract must reference the schema it is bound to: a contract without its schema is a promise about data nobody can check (%s)", [contract_file]),
		"path": "$.contract.schema",
	}
}

f_schema contains finding if {
	is_object(schema_doc)
	not lib.is_nonempty_string(schema_ref)
	finding := {
		"severity": "error",
		"rule": "schema/ref-required",
		"message": sprintf("the schema clause must carry the schema's reference (ref): field names and types that live nowhere check nothing (%s)", [contract_file]),
		"path": "$.contract.schema.ref",
	}
}

f_schema contains finding if {
	is_object(schema_doc)
	not lib.is_nonempty_string(schema_subject)
	finding := {
		"severity": "error",
		"rule": "schema/subject-required",
		"message": sprintf("the schema clause must say what one record of the dataset is (subject): a schema that does not name its subject is a shape in search of data (%s)", [contract_file]),
		"path": "$.contract.schema.subject",
	}
}

# --- findings: the freshness clause ---------------------------------------------------

f_freshness contains finding if {
	is_object(contract_doc)
	not is_object(object.get(contract_doc, "freshness", null))
	finding := {
		"severity": "error",
		"rule": "freshness/required",
		"message": sprintf("the data contract must carry a freshness clause: a dataset that is arbitrarily stale has breached no promise, because it made none (%s)", [contract_file]),
		"path": "$.contract.freshness",
	}
}

f_freshness contains finding if {
	is_object(freshness_doc)
	freshness_sla == null
	finding := {
		"severity": "error",
		"rule": "freshness/sla-required",
		"message": sprintf("the freshness clause must carry its SLA (slaHours): a freshness clause without an SLA is a promise of freshness with no number to breach (%s)", [contract_file]),
		"path": "$.contract.freshness.slaHours",
	}
}

f_freshness contains finding if {
	is_object(freshness_doc)
	freshness_sla != null
	not is_positive_number(freshness_sla)
	finding := {
		"severity": "error",
		"rule": "freshness/sla-invalid",
		"message": sprintf("the freshness SLA must be a positive number of hours — a zero-hour SLA is no SLA at all (%s)", [contract_file]),
		"path": "$.contract.freshness.slaHours",
	}
}

# --- findings: the quality thresholds -------------------------------------------------

f_quality contains finding if {
	is_object(contract_doc)
	not is_array(object.get(contract_doc, "quality", null))
	finding := {
		"severity": "error",
		"rule": "quality/required",
		"message": sprintf("the data contract must declare its quality thresholds as an array of {metric, min or max} rows (%s)", [contract_file]),
		"path": "$.contract.quality",
	}
}

f_quality contains finding if {
	is_object(contract_doc)
	is_array(object.get(contract_doc, "quality", null))
	count(object.get(contract_doc, "quality", [])) == 0
	finding := {
		"severity": "error",
		"rule": "quality/threshold-required",
		"message": sprintf("the data contract must name at least one quality threshold: quality nobody promised is quality nobody has to keep (%s)", [contract_file]),
		"path": "$.contract.quality",
	}
}

f_quality contains finding if {
	is_object(contract_doc)
	is_array(object.get(contract_doc, "quality", null))
	some q in object.get(contract_doc, "quality", [])
	not is_object(q)
	finding := {
		"severity": "error",
		"rule": "quality/row-must-be-object",
		"message": sprintf("every quality threshold must be an object: {metric, min or max} (%s)", [contract_file]),
		"path": "$.contract.quality",
	}
}

f_quality contains finding if {
	some q in quality_rows
	not lib.is_nonempty_string(quality_metric(q))
	finding := {
		"severity": "error",
		"rule": "quality/metric-required",
		"message": sprintf("every quality threshold must name the metric it bounds (%s)", [contract_file]),
		"path": "$.contract.quality",
	}
}

f_quality contains finding if {
	some q in quality_rows
	quality_bound_count(q) == 0
	finding := {
		"severity": "error",
		"rule": "quality/bound-required",
		"message": sprintf("the quality threshold for '%v' carries neither a min nor a max: a threshold without a number is a wish (%s)", [quality_metric(q), contract_file]),
		"path": "$.contract.quality",
	}
}

f_quality contains finding if {
	some q in quality_rows
	quality_bound_count(q) == 2
	finding := {
		"severity": "error",
		"rule": "quality/bound-ambiguous",
		"message": sprintf("the quality threshold for '%v' carries both a min and a max: a metric is bounded exactly one way (%s)", [quality_metric(q), contract_file]),
		"path": "$.contract.quality",
	}
}

f_quality contains finding if {
	some q in quality_rows
	some k in {"min", "max"}
	bound := object.get(q, k, null)
	bound != null
	not is_number(bound)
	finding := {
		"severity": "error",
		"rule": "quality/bound-invalid",
		"message": sprintf("the quality threshold's %v must be a number — '%v' is not a threshold the validator agreed to read (%s)", [k, bound, contract_file]),
		"path": "$.contract.quality",
	}
}

f_quality contains finding if {
	some q in quality_rows
	lib.is_nonempty_string(quality_metric(q))
	count([x | some x in quality_rows; quality_metric(x) == quality_metric(q)]) > 1
	finding := {
		"severity": "error",
		"rule": "quality/duplicate",
		"message": sprintf("the quality threshold '%v' is declared more than once: one metric, one row (%s)", [quality_metric(q), contract_file]),
		"path": "$.contract.quality",
	}
}

# --- findings: the consumers --------------------------------------------------------

f_consumers contains finding if {
	is_object(contract_doc)
	not is_array(object.get(contract_doc, "consumers", null))
	finding := {
		"severity": "error",
		"rule": "consumers/required",
		"message": sprintf("the data contract must name its consumers as an array of {name, use} rows (%s)", [contract_file]),
		"path": "$.contract.consumers",
	}
}

f_consumers contains finding if {
	is_object(contract_doc)
	is_array(object.get(contract_doc, "consumers", null))
	count(object.get(contract_doc, "consumers", [])) == 0
	finding := {
		"severity": "error",
		"rule": "consumers/required",
		"message": sprintf("the data contract must name at least one consumer: a contract with no named consumer is a promise made to nobody, and a deprecation window negotiated with no one (%s)", [contract_file]),
		"path": "$.contract.consumers",
	}
}

f_consumers contains finding if {
	is_object(contract_doc)
	is_array(object.get(contract_doc, "consumers", null))
	some c in object.get(contract_doc, "consumers", [])
	not is_object(c)
	finding := {
		"severity": "error",
		"rule": "consumers/row-must-be-object",
		"message": sprintf("every consumer row must be an object: {name, use} (%s)", [contract_file]),
		"path": "$.contract.consumers",
	}
}

f_consumers contains finding if {
	some c in consumer_rows
	not lib.is_nonempty_string(consumer_name(c))
	finding := {
		"severity": "error",
		"rule": "consumer/name-required",
		"message": sprintf("every consumer row must name the consumer: a consumer with no name is nobody to warn before the schema breaks them (%s)", [contract_file]),
		"path": "$.contract.consumers",
	}
}

f_consumers contains finding if {
	some c in consumer_rows
	not lib.is_nonempty_string(consumer_use(c))
	finding := {
		"severity": "error",
		"rule": "consumer/use-required",
		"message": sprintf("every consumer row must say what the consumer uses the dataset for (use): the use names which clause their breakage will breach (%s)", [contract_file]),
		"path": "$.contract.consumers",
	}
}

f_consumers contains finding if {
	some c in consumer_rows
	lib.is_nonempty_string(consumer_name(c))
	count([x | some x in consumer_rows; consumer_name(x) == consumer_name(c)]) > 1
	finding := {
		"severity": "error",
		"rule": "consumer/duplicate",
		"message": sprintf("the consumer '%v' is named more than once: one consumer, one row (%s)", [consumer_name(c), contract_file]),
		"path": "$.contract.consumers",
	}
}

# --- findings: the checks that enforce the contract in CI ------------------------------

f_enforcement contains finding if {
	is_object(contract_doc)
	not is_array(object.get(contract_doc, "enforcement", null))
	finding := {
		"severity": "error",
		"rule": "enforcement/required",
		"message": sprintf("the data contract must declare the checks that enforce it in CI: an unenforced contract is a promise nobody keeps (%s)", [contract_file]),
		"path": "$.contract.enforcement",
	}
}

f_enforcement contains finding if {
	is_object(contract_doc)
	is_array(object.get(contract_doc, "enforcement", null))
	count(object.get(contract_doc, "enforcement", [])) == 0
	finding := {
		"severity": "error",
		"rule": "enforcement/check-required",
		"message": sprintf("the enforcement clause must name at least one check that runs in CI: evidence of enforcement is the contract's own clause (%s)", [contract_file]),
		"path": "$.contract.enforcement",
	}
}

f_enforcement contains finding if {
	is_object(contract_doc)
	is_array(object.get(contract_doc, "enforcement", null))
	some c in object.get(contract_doc, "enforcement", [])
	not is_object(c)
	finding := {
		"severity": "error",
		"rule": "enforcement/row-must-be-object",
		"message": sprintf("every enforcement row must be an object: {check, pipeline} (%s)", [contract_file]),
		"path": "$.contract.enforcement",
	}
}

f_enforcement contains finding if {
	some c in check_rows
	not lib.is_nonempty_string(check_name(c))
	finding := {
		"severity": "error",
		"rule": "check/name-required",
		"message": sprintf("every enforcement row must name its check (check): the enforcement record answers for checks by name (%s)", [contract_file]),
		"path": "$.contract.enforcement",
	}
}

f_enforcement contains finding if {
	some c in check_rows
	not lib.is_nonempty_string(check_pipeline(c))
	finding := {
		"severity": "error",
		"rule": "check/pipeline-required",
		"message": sprintf("every check must name the pipeline that runs it (pipeline): a check that runs nowhere is not evidence of enforcement (%s)", [contract_file]),
		"path": "$.contract.enforcement",
	}
}

f_enforcement contains finding if {
	some c in check_rows
	lib.is_nonempty_string(check_name(c))
	count([x | some x in check_rows; check_name(x) == check_name(c)]) > 1
	finding := {
		"severity": "error",
		"rule": "check/duplicate",
		"message": sprintf("the check '%v' is declared more than once: one check, one row (%s)", [check_name(c), contract_file]),
		"path": "$.contract.enforcement",
	}
}

# --- findings: the change methodology ---------------------------------------------------

f_changes contains finding if {
	is_object(contract_doc)
	not is_object(object.get(contract_doc, "changes", null))
	finding := {
		"severity": "error",
		"rule": "changes/required",
		"message": sprintf("the data contract must carry its changes clause: how the dataset evolves is part of the promise, not an afterthought (%s)", [contract_file]),
		"path": "$.contract.changes",
	}
}

f_changes contains finding if {
	is_object(changes_doc)
	not lib.is_nonempty_string(changes_methodology)
	finding := {
		"severity": "error",
		"rule": "changes/methodology-required",
		"message": sprintf("the changes clause must name its change methodology: consumers negotiate against a discipline, not against hope (%s)", [contract_file]),
		"path": "$.contract.changes.methodology",
	}
}

f_changes contains finding if {
	is_object(changes_doc)
	lib.is_nonempty_string(changes_methodology)
	not methodology_known(changes_methodology)
	finding := {
		"severity": "error",
		"rule": "changes/methodology-unknown",
		"message": sprintf("the changes clause names the methodology '%v', which the validator never agreed to model: expand-migrate-contract (%s)", [changes_methodology, contract_file]),
		"path": "$.contract.changes.methodology",
	}
}

f_changes contains finding if {
	is_object(changes_doc)
	changes_deprecation_days == null
	finding := {
		"severity": "error",
		"rule": "changes/deprecation-window-required",
		"message": sprintf("the changes clause must carry its deprecation window in days (deprecationWindowDays): windows are measured, not calendared — 'sometime in Q3' is not a window (%s)", [contract_file]),
		"path": "$.contract.changes.deprecationWindowDays",
	}
}

f_changes contains finding if {
	is_object(changes_doc)
	changes_deprecation_days != null
	not is_positive_number(changes_deprecation_days)
	finding := {
		"severity": "error",
		"rule": "changes/deprecation-window-invalid",
		"message": sprintf("the deprecation window must be a positive number of days — a zero-day window is a breaking change wearing yesterday's date (%s)", [contract_file]),
		"path": "$.contract.changes.deprecationWindowDays",
	}
}

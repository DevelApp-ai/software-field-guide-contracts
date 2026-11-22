# Data contract conformance gate — The Software Field Guide,
# issue #106.
#
# The contract declares the dataset's promises — and names the
# checks that enforce it in CI; the enforcement record is the CI's
# word, the checks it actually ran for one dataset, and the day each
# ran. This gate joins the two documents and refuses — a conformance
# gate, not an advisor: a contract whose evidence does not back it
# does not ship. The three drifts the gate knows by name: evidence
# for a dataset the contract never names (the record answers for
# another dataset), a declared check the record never shows running
# (a check the contract swears by and the pipelines never swore),
# and evidence for a check the contract never declared (a run row
# the contract cannot vouch for). What also fails the gate is a
# document the gate cannot read — a contract or an enforcement
# record with broken stamps or shapes is a question the gate
# refuses to answer on its own inputs. The verdict ladder separates
# the two honestly: unreadable (a document is malformed), drifts
# (only join drifts), consistent. The cards render the whole board:
# one row per declared check.
#
# Input (JSON): {"contract": {...}, "enforcement": {...},
#                "today": "YYYY-MM-DD", "contractFile": "...",
#                "enforcementFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package datacontract

import rego.v1

import data.datacontract.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"cards": advice_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := ((((((validate_findings | g_evidence_missing) | g_evidence_stamps) | g_evidence_shape) | g_evidence_rows) | g_dataset_mismatch) | g_check_never_run) | g_check_undeclared

# --- findings: the enforcement record at the gate -------------------------------

g_evidence_missing contains finding if {
	not is_object(evidence_doc)
	finding := {
		"severity": "error",
		"rule": "evidence/missing",
		"message": "the enforcement record is required at the gate: pass it as input.enforcement — whether enforcement actually runs is the CI's word, not the contract's",
		"path": "$.enforcement",
	}
}

g_evidence_stamps contains finding if {
	is_object(evidence_doc)
	not is_positive_integer(object.get(evidence_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "evidence/version-required",
		"message": sprintf("the enforcement record must carry a version (a positive integer): run evidence is versioned like the contract it answers for (%s)", [enforcement_file]),
		"path": "$.enforcement.version",
	}
}

g_evidence_stamps contains finding if {
	is_object(evidence_doc)
	not lib.is_valid_date(object.get(evidence_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "evidence/reviewed-on-invalid",
		"message": sprintf("the enforcement record must carry reviewedOn as a real YYYY-MM-DD date (%s)", [enforcement_file]),
		"path": "$.enforcement.reviewedOn",
	}
}

g_evidence_stamps contains finding if {
	is_object(evidence_doc)
	lib.is_valid_date(object.get(evidence_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(evidence_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "evidence/reviewed-in-future",
		"message": sprintf("the enforcement record carries a reviewedOn date in the future (%s)", [enforcement_file]),
		"path": "$.enforcement.reviewedOn",
	}
}

g_evidence_stamps contains finding if {
	is_object(evidence_doc)
	lib.is_valid_date(object.get(evidence_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(evidence_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "evidence/reviewed-stale",
		"message": sprintf("the enforcement record was reviewed more than 365 days before today: a record nobody re-reads is evidence nobody would still vouch for (%s)", [enforcement_file]),
		"path": "$.enforcement.reviewedOn",
	}
}

g_evidence_stamps contains finding if {
	is_object(evidence_doc)
	not lib.is_nonempty_string(object.get(evidence_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "evidence/owner-required",
		"message": sprintf("the enforcement record must name an owner: run evidence without an owner is a record nobody maintains (%s)", [enforcement_file]),
		"path": "$.enforcement.owner",
	}
}

g_evidence_stamps contains finding if {
	is_object(evidence_doc)
	not lib.is_nonempty_string(evidence_dataset)
	finding := {
		"severity": "error",
		"rule": "evidence/dataset-required",
		"message": sprintf("the enforcement record must name the dataset its evidence answers for: the dataset is the join key the contract is judged against (%s)", [enforcement_file]),
		"path": "$.enforcement.dataset",
	}
}

# --- findings: the enforcement record's run rows -----------------------------------

g_evidence_shape contains finding if {
	is_object(evidence_doc)
	not is_array(object.get(evidence_doc, "runs", null))
	finding := {
		"severity": "error",
		"rule": "evidence/runs-must-be-array",
		"message": sprintf("the enforcement record's runs must be an array of {check, ranOn} rows (%s)", [enforcement_file]),
		"path": "$.enforcement.runs",
	}
}

g_evidence_shape contains finding if {
	is_object(evidence_doc)
	is_array(object.get(evidence_doc, "runs", null))
	some r in object.get(evidence_doc, "runs", [])
	not is_object(r)
	finding := {
		"severity": "error",
		"rule": "evidence/row-must-be-object",
		"message": sprintf("every run row must be an object: {check, ranOn} (%s)", [enforcement_file]),
		"path": "$.enforcement.runs",
	}
}

g_evidence_rows contains finding if {
	some r in run_rows
	not lib.is_nonempty_string(run_check(r))
	finding := {
		"severity": "error",
		"rule": "run/check-required",
		"message": sprintf("every run row must name the check it ran: evidence for an unnamed check is evidence of nothing (%s)", [enforcement_file]),
		"path": "$.enforcement.runs",
	}
}

g_evidence_rows contains finding if {
	some r in run_rows
	not lib.is_valid_date(run_on(r))
	finding := {
		"severity": "error",
		"rule": "run/ran-on-invalid",
		"message": sprintf("every run row must carry its day as a real YYYY-MM-DD date (ranOn) (%s)", [enforcement_file]),
		"path": "$.enforcement.runs",
	}
}

g_evidence_rows contains finding if {
	some r in run_rows
	lib.is_valid_date(run_on(r))
	lib.is_valid_date(today_date)
	lib.date_to_days(run_on(r)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "run/ran-in-future",
		"message": sprintf("a run row carries a ranOn date in the future: evidence dated after today is evidence that has not happened (%s)", [enforcement_file]),
		"path": "$.enforcement.runs",
	}
}

g_evidence_rows contains finding if {
	some r in run_rows
	lib.is_nonempty_string(run_check(r))
	count([x | some x in run_rows; run_check(x) == run_check(r)]) > 1
	finding := {
		"severity": "error",
		"rule": "run/duplicate",
		"message": sprintf("the record carries more than one run row for the check '%v': one check, one row per record (%s)", [run_check(r), enforcement_file]),
		"path": "$.enforcement.runs",
	}
}

# --- the three drifts, named -----------------------------------------------------

# (1) The dataset mismatch: the contract governs one dataset, and
# the record answers for another. Evidence for a dataset the
# contract never names is evidence for somebody else's promises.
g_dataset_mismatch contains finding if {
	is_object(contract_doc)
	is_object(evidence_doc)
	lib.is_nonempty_string(dataset_name)
	lib.is_nonempty_string(evidence_dataset)
	evidence_dataset != dataset_name
	finding := {
		"severity": "error",
		"rule": "gate/dataset-mismatch",
		"message": sprintf("the enforcement record answers for the dataset '%v', which the contract never names: evidence for somebody else's promises is not evidence here (%s, %s)", [evidence_dataset, contract_file, enforcement_file]),
		"path": "$.enforcement.dataset",
	}
}

# (2) The check that never ran: the contract declares the check,
# swears the pipelines run it, and the record shows no such run. A
# check the contract swears by and the CI never swore is a clause
# with no teeth.
g_check_never_run contains finding if {
	some c in check_rows
	lib.is_nonempty_string(check_name(c))
	not check_run(check_name(c))
	finding := {
		"severity": "error",
		"rule": "gate/check-never-run",
		"message": sprintf("the contract declares the check '%v', but the enforcement record shows it never running: a declared check without a run is enforcement evidence that does not exist (%s, %s)", [check_name(c), contract_file, enforcement_file]),
		"path": "$.contract.enforcement",
	}
}

# (3) The undeclared check: the record shows a run the contract
# never declared. Run rows the contract cannot vouch for are logs,
# not enforcement.
g_check_undeclared contains finding if {
	some r in run_rows
	lib.is_nonempty_string(run_check(r))
	is_object(contract_doc)
	is_array(object.get(contract_doc, "enforcement", null))
	not check_declared(run_check(r))
	finding := {
		"severity": "error",
		"rule": "gate/check-undeclared",
		"message": sprintf("the enforcement record shows a run of '%v', a check the contract never declared: run rows the contract cannot vouch for are logs, not enforcement (%s, %s)", [run_check(r), contract_file, enforcement_file]),
		"path": "$.enforcement.runs",
	}
}

# --- the cards -----------------------------------------------------------------

# The board: one row per declared check. Only well-formed declared
# checks render; a malformed clause is a finding, not a card.
advice_cards := sort([card |
	some c in check_rows
	lib.is_nonempty_string(check_name(c))
	card := {
		"area": "checks",
		"item": check_name(c),
		"verdict": check_card_verdict(check_name(c)),
		"detail": check_card_detail(check_name(c)),
	}
])

check_card_verdict(name) := "consistent" if check_run(name)

check_card_verdict(name) := "drifts" if not check_run(name)

check_card_detail(name) := sprintf("declared, run %v per the enforcement record (%s, %s)", [last_run_on(name), contract_file, enforcement_file]) if {
	check_run(name)
}

check_card_detail(name) := sprintf("declared, but no run row in the enforcement record names it (%s, %s)", [contract_file, enforcement_file]) if {
	not check_run(name)
}

# --- the verdict ladder -----------------------------------------------------------

# The conformance ladder, honest about what each rung means: a
# document the gate cannot read is a question the gate refuses to
# answer; drifts are conformance failures the contract must fix
# before its evidence is believed; a contract whose every declared
# check shows its run in a record that answers for its dataset is
# consistent.
gate_verdict(fs) := "unreadable" if {
	some f in fs
	not startswith(f.rule, "gate/")
}

gate_verdict(fs) := "drifts" if {
	count([f | some f in fs; not startswith(f.rule, "gate/")]) == 0
	count(fs) > 0
}

gate_verdict(fs) := "consistent" if {
	count(fs) == 0
}

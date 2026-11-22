# Data contract conformance audit — The Software Field Guide,
# issue #106.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the data contract
# validated (its schema, freshness, quality, consumers, enforcement,
# and changes clauses) and the contract judged against the
# enforcement record (the dataset join, the check that never ran,
# and the run the contract never declared) — one verdict, one
# findings list, the conformance cards alongside. The findings of the
# two analyzers are sets, so a shared condition (input nobody can
# read, a contract that is not there, an anchor date that is not a
# date) is reported once, not twice.
#
# Input (JSON): {"contract": {...}, "enforcement": {...},
#                "today": "YYYY-MM-DD", "contractFile": "...",
#                "enforcementFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package datacontract

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"cards": advice_cards,
		"verdict": gate_verdict(fs),
	}
}

audit_findings := validate_findings | gate_findings

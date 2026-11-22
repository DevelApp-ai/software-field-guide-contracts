# Component-lifecycle consistency audit — The Software Field Guide,
# issue #105.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the lifecycle record
# validated (its stamps, its review clock, every transition with the
# evidence its type demands) and the record joined against the
# component package manifest (the mismatched component) — one
# verdict, one findings list, the transition cards alongside. The
# findings of the two analyzers are sets, so a shared condition
# (input nobody can read, a record that is not there, an anchor date
# that is not a date) is reported once, not twice.
#
# Input (JSON): {"lifecycle": {...}, "package": {...},
#                "today": "YYYY-MM-DD", "lifecycleFile": "...",
#                "packageFile": "..."}
# Result:       {"valid": bool, "findings": [...], "transitions": [...], "verdict": "..."}
package lifecycle

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"transitions": transition_cards,
		"verdict": gate_verdict(fs),
	}
}

audit_findings := validate_findings | gate_findings

# Compliance controls-as-data audit — The Software Field Guide,
# issue #107.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the controls
# manifest validated (its stamps, its evidence sources, its control
# rows and their mappings, citations, and review clocks) and the
# controls joined against the requirements catalog (the unmapped
# requirement, the unknown requirement, the dead evidence, the
# lapsed clock) — one verdict, one findings list, the requirement
# cards alongside. The findings of the two analyzers are sets, so a
# shared condition (input nobody can read, a manifest that is not
# there, an anchor date that is not a date) is reported once, not
# twice.
#
# Input (JSON): {"controls": {...}, "requirements": {...},
#                "today": "YYYY-MM-DD", "controlsFile": "...",
#                "requirementsFile": "..."}
# Result:       {"valid": bool, "findings": [...], "requirements": [...], "verdict": "..."}
package compliance

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"requirements": requirement_cards,
		"verdict": gate_verdict(fs),
	}
}

audit_findings := validate_findings | gate_findings

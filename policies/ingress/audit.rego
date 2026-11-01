# Ingress posture audit — The Software Field Guide, issue #82.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the posture case
# validated (wildcards contained inside the zone, default-deny,
# certificate rotation clocks, SLOs with pagers, every route class
# logged) and the kill path gated against the drill record
# (rehearsed, inside the staleness clock) — one verdict, one
# findings list, the posture cards alongside. The findings of the
# two analyzers are sets, so a shared condition (input nobody can
# read, a case that is not there, an anchor date that is not a
# date) is reported once, not twice.
#
# Input (JSON): {"case": {...}, "drill": {...}, "today": "YYYY-MM-DD",
#                "caseFile": "...", "drillFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package ingress

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"cards": posture_cards,
		"verdict": gate_verdict(fs),
	}
}

audit_findings := validate_findings | gate_findings

# Alert-to-record linkage audit — The Software Field Guide, issue #69.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the alerting contract
# validated (ladder, runbooks with escalation clocks, alert rules with
# owners and record destinations) and the incident register gated
# against it (every fired alert linked to a record, every severity on
# the ladder as it stood at detection time, every postmortem action
# closed with verification) — one verdict, one findings list, the
# alert-to-record linkages alongside. The findings of the two analyzers
# are sets, so a shared condition (a missing contract) is reported
# once, not twice.
#
# Input (JSON): {"alerting": {...}, "register": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [...], "linkages": [...]}
package alerts

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"linkages": linkages,
	}
}

audit_findings := validate_findings | gate_findings

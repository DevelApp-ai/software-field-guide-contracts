# Action scope audit — The Software Field Guide, issue #70.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the action registry
# validated (named, typed, parameter-checked actions with envelopes
# under the platform ceilings, isolation demanded for scripted types,
# explicit confirmation demanded at consequential levels, external
# references pointed at registered, approved servers) and the agent
# permission manifest gated against it (no phantom grants, no scopes
# on undeclared parameters, no stage contradictions, no quarantined
# agents with grants) — one verdict, one findings list, the per-agent
# scoping alongside. The findings of the two analyzers are sets, so a
# shared condition (a missing registry) is reported once, not twice.
#
# Input (JSON): {"registry": {...}, "manifest": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [...], "scoping": [...]}
package actions

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"scoping": scoping,
	}
}

audit_findings := validate_findings | gate_findings

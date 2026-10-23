# Observability audit — The Software Field Guide, issue #61.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the three contract
# documents validated, the instrumentation scan linted against both
# vocabularies, and the metrics export gated against the cardinality
# budget — one verdict, one findings list, the per-metric cardinalities
# alongside. The findings of the three analyzers are sets, so a shared
# condition (a missing document) is reported once, not three times.
#
# Input (JSON): {"vocabulary": {...}, "labels": {...}, "budget": {...},
#                "today": "YYYY-MM-DD", "scan": {...},
#                "observations": [...], "budgetFile": "..." (optional)}
# Result:       {"valid": bool, "findings": [...], "cardinalities": [...]}
package obs

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"cardinalities": cardinalities,
	}
}

audit_findings := (validate_findings | lint_findings) | gate_findings

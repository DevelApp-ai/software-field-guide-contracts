# Segment render-consistency audit — The Software Field Guide,
# issue #80.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the segment contract
# validated (named rules between declared segments, TTL-bound
# exceptions unexpired) and the renders, flow evidence, and promotion
# gated against it (every rule present in every declared render, no
# phantom rules, the modeled subset agreeing, the promotion PR
# citing evidence it holds, no rule left dead) — one verdict, one
# findings list, the per-rule cards alongside. The findings of the
# two analyzers are sets, so a shared condition (a missing contract)
# is reported once, not twice.
#
# Input (JSON): {"contract": {...}, "renders": {...}, "flows": {...},
#                "promotion": {...}, "today": "YYYY-MM-DD", ...file names}
# Result:       {"valid": bool, "findings": [...], "rules": [...], "verdict": "..."}
package segment

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"rules": rule_cards,
		"verdict": gate_verdict(fs),
	}
}

audit_findings := validate_findings | gate_findings

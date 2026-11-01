# Deletion evidence audit — The Software Field Guide, issue #79.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the DEK registry
# validated (named keys, states, and destruction evidence) and the
# erasure case gated against it (every inventory store swept or
# honestly pending, the backup windows declared, the tenant's keys
# destroyed) — one verdict, one findings list, the per-store evidence
# alongside. The findings of the two analyzers are sets, so a shared
# condition (a missing registry) is reported once, not twice.
#
# Input (JSON): {"keys": {...}, "case": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [...], "stores": [...], "verdict": "..."}
package erasure

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"stores": store_cards,
		"verdict": case_verdict(fs),
	}
}

audit_findings := validate_findings | gate_findings

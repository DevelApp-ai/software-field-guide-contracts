# Citizen spec-rails audit — The Software Field Guide, issue #84.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the app manifest
# validated (components with behaviors, bindings with names, modes,
# and rails, actions used, guardrails with versions) and the app
# judged against its spec and the platform's registry (escape
# hatches, actions outside the rails, behaviors without coverage,
# guardrails below the floor) — one verdict, one findings list, the
# advice cards alongside. The findings of the two analyzers are
# sets, so a shared condition (input nobody can read, a manifest
# that is not there, an anchor date that is not a date) is reported
# once, not twice.
#
# Input (JSON): {"manifest": {...}, "spec": {...}, "registry": {...},
#                "today": "YYYY-MM-DD", "manifestFile": "...",
#                "specFile": "...", "registryFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package citizen

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

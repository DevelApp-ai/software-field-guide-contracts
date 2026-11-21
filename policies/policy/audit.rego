# Policy-component validation audit — The Software Field Guide,
# issue #103.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the policy
# component catalog validated (its stamps, its admitted policy
# rows, each versioned, signed over its digest, postured on the
# ladder, and bound to one exact path) and the package's policy
# bindings joined against it (the unresolved binding, the path
# drift) — one verdict, one findings list, the policy cards
# alongside. The findings of the two analyzers are sets, so a
# shared condition (input nobody can read, a catalog that is not
# there, an anchor date that is not a date) is reported once, not
# twice.
#
# Input (JSON): {"catalog": {...}, "package": {...},
#                "today": "YYYY-MM-DD", "catalogFile": "...",
#                "packageFile": "..."}
# Result:       {"valid": bool, "findings": [...], "policies": [...], "verdict": "..."}
package policy

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"policies": policy_cards,
		"verdict": gate_verdict(fs),
	}
}

audit_findings := validate_findings | gate_findings

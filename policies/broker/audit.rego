# Supply-chain IAM-broker scope audit — The Software Field Guide,
# issue #104.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the broker grant
# document validated (its stamps, its declared principals, every
# grant's named identity, pinned digest, exact action set, and
# expiry) and the grants joined against the component package
# manifest (the unresolved component, the digest drift) — one
# verdict, one findings list, the grant cards alongside. The
# findings of the two analyzers are sets, so a shared condition
# (input nobody can read, a grant document that is not there, an
# anchor date that is not a date) is reported once, not twice.
#
# Input (JSON): {"broker": {...}, "package": {...},
#                "today": "YYYY-MM-DD", "brokerFile": "...",
#                "packageFile": "..."}
# Result:       {"valid": bool, "findings": [...], "grants": [...], "verdict": "..."}
package broker

import rego.v1

# --- entrypoint -------------------------------------------------------------

audit := result if {
	fs := sort([f | some f in audit_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"grants": grant_cards,
		"verdict": gate_verdict(fs),
	}
}

audit_findings := validate_findings | gate_findings

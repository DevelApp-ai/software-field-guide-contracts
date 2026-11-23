# Identity and secrets scope audit — The Software Field Guide,
# issue #108.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the identity
# manifest validated alone (its stamps, its identities, and the
# scope minimality of every reference it declares) and the manifest
# judged against the secrets catalog (the unresolved reference, the
# identity the catalog never admitted, the scope mismatch, and the
# rotation clock that ran out) — one verdict, one findings list, the
# reference cards alongside. The findings of the two analyzers are
# sets, so a shared condition (input nobody can read, a manifest
# that is not there, an anchor date that is not a date) is reported
# once, not twice.
#
# Input (JSON): {"manifest": {...}, "catalog": {...},
#                "today": "YYYY-MM-DD", "manifestFile": "...",
#                "catalogFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package identity

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

# Component package conformance audit — The Software Field Guide,
# issue #101.
#
# The composed entry point for the browser playground and any caller
# that wants the whole answer in one evaluation: the package
# manifest validated (its identity and tier, the artifact digest,
# the recorded signature, attestation, and provenance, the pinned
# dependencies) and the package judged against the component
# registry (unregistered, drifted from its registration, and the
# three dependency drifts) — one verdict, one findings list, the
# conformance cards alongside. The findings of the two analyzers are
# sets, so a shared condition (input nobody can read, a package
# manifest that is not there, an anchor date that is not a date) is
# reported once, not twice.
#
# Input (JSON): {"package": {...}, "registry": {...},
#                "today": "YYYY-MM-DD", "packageFile": "...",
#                "registryFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package component

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

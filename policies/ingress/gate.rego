# Ingress posture gate — The Software Field Guide, issue #82.
#
# The case declares its kill path; the drill record proves it still
# works. This gate joins the two documents and fails loudly when the
# join is broken: a drill record with no stamps of its own (drill/
# version-required, drill/owner-required), a rehearsal row that
# names a kill path the case never declares (drill/killpath-
# unknown), a drill dated in the future (drill/future-dated — a
# rehearsal recorded in the future is a rehearsal that has not
# happened), a kill path declared but never rehearsed (killpath/
# never-rehearsed), and a rehearsal grown stale beyond the drill
# record's staleness clock (killpath/stale-rehearsal — a kill path
# rehearsed once and never again is a kill path that has drifted).
# The posture cards render the whole board: one row per judged item
# across the six areas of the case, hardened, review, or exposed.
#
# Input (JSON): {"case": {...}, "drill": {...}, "today": "YYYY-MM-DD",
#                "caseFile": "...", "drillFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package ingress

import rego.v1

import data.ingress.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"cards": posture_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := ((((((f_input_invalid | f_today_invalid) | f_case_missing) | g_drill_stamps) | g_drills_shape) | g_drills_content) | g_drill_joins) | g_rehearsal

# --- findings: the drill record's own stamps -------------------------------------

# The drill record is evidence, and evidence has a shelf life: a
# drill nobody re-reads is a drill nobody still believes.
g_drill_stamps contains finding if {
	is_object(drill_doc)
	not is_positive_integer(object.get(drill_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "drill/version-required",
		"message": sprintf("the drill record must carry a version (a positive integer): the rehearsals are versioned like the case they rehearse (%s)", [drill_file]),
		"path": "$.drill.version",
	}
}

g_drill_stamps contains finding if {
	is_object(drill_doc)
	not lib.is_valid_date(object.get(drill_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "drill/reviewed-on-invalid",
		"message": sprintf("the drill record must carry reviewedOn as a real YYYY-MM-DD date (%s)", [drill_file]),
		"path": "$.drill.reviewedOn",
	}
}

g_drill_stamps contains finding if {
	is_object(drill_doc)
	lib.is_valid_date(object.get(drill_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(drill_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "drill/reviewed-in-future",
		"message": sprintf("the drill record carries a reviewedOn date in the future (%s)", [drill_file]),
		"path": "$.drill.reviewedOn",
	}
}

g_drill_stamps contains finding if {
	is_object(drill_doc)
	not lib.is_nonempty_string(object.get(drill_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "drill/owner-required",
		"message": sprintf("the drill record must name an owner: a rehearsal with an owner and a review cadence is the discipline (%s)", [drill_file]),
		"path": "$.drill.owner",
	}
}

# --- findings: the rehearsal rows ----------------------------------------------

g_drills_shape contains finding if {
	is_object(drill_doc)
	not is_array(object.get(drill_doc, "drills", null))
	finding := {
		"severity": "error",
		"rule": "drills/must-be-array",
		"message": sprintf("drills must be an array of the rehearsals on record: each row names a kill path, a date, and its evidence (%s)", [drill_file]),
		"path": "$.drill.drills",
	}
}

g_drills_shape contains finding if {
	is_object(drill_doc)
	is_array(object.get(drill_doc, "drills", null))
	some d in object.get(drill_doc, "drills", [])
	not is_object(d)
	finding := {
		"severity": "error",
		"rule": "drills/row-must-be-object",
		"message": "every rehearsal row must be an object: {killPath, drilledOn, evidence}",
		"path": "$.drill.drills",
	}
}

g_drills_content contains finding if {
	some d in drills
	not lib.is_nonempty_string(drill_kill_path(d))
	finding := {
		"severity": "error",
		"rule": "drill/killpath-required",
		"message": sprintf("every rehearsal row must name the kill path it rehearses (%s)", [drill_file]),
		"path": "$.drill.drills",
	}
}

g_drills_content contains finding if {
	some d in drills
	lib.is_nonempty_string(drill_kill_path(d))
	not lib.is_valid_date(drill_drilled_on(d))
	finding := {
		"severity": "error",
		"rule": "drill/drilled-on-required",
		"message": sprintf("every rehearsal row must carry drilledOn as a real YYYY-MM-DD date (%s)", [drill_file]),
		"path": "$.drill.drills",
	}
}

g_drills_content contains finding if {
	some d in drills
	lib.is_nonempty_string(drill_kill_path(d))
	not lib.is_nonempty_string(drill_evidence(d))
	finding := {
		"severity": "error",
		"rule": "drill/evidence-required",
		"message": sprintf("every rehearsal row must cite its evidence: a rehearsal without a record is a rumor (%s)", [drill_file]),
		"path": "$.drill.drills",
	}
}

# A rehearsal recorded in the future is a rehearsal that has not
# happened — and never softens the kill path's posture.
g_drills_content contains finding if {
	some d in drills
	lib.is_nonempty_string(drill_kill_path(d))
	lib.is_valid_date(drill_drilled_on(d))
	lib.is_valid_date(today_date)
	lib.date_to_days(drill_drilled_on(d)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "drill/future-dated",
		"message": sprintf("the rehearsal of '%s' is dated %s, after the anchor date: a drill recorded in the future is a drill that has not happened (%s)", [drill_kill_path(d), drill_drilled_on(d), drill_file]),
		"path": "$.drill.drills",
	}
}

# --- findings: the case × drill join --------------------------------------------

# A rehearsal of a kill path the case never declares is a rehearsal
# of a promise the platform never made.
g_drill_joins contains finding if {
	is_object(drill_doc)
	is_object(case_doc)
	some d in drills
	lib.is_nonempty_string(drill_kill_path(d))
	not case_declares_kill_path(drill_kill_path(d))
	finding := {
		"severity": "error",
		"rule": "drill/killpath-unknown",
		"message": sprintf("the drill record rehearses kill path '%s', which the posture case never declares: the two documents describe different platforms (%s vs %s)", [drill_kill_path(d), drill_file, case_file]),
		"path": "$.drill.drills",
	}
}

# --- findings: the kill path's rehearsal clock ------------------------------------

# A kill path declared but never rehearsed is a promise the platform
# has never kept — with no drill record in hand, or with a drill
# record that holds no rehearsal naming it.
g_rehearsal contains finding if {
	kill_path_declared
	not is_object(drill_doc)
	finding := {
		"severity": "error",
		"rule": "killpath/never-rehearsed",
		"message": sprintf("the kill path '%s' is declared but no drill record was given: a kill path never rehearsed is a lever nobody has ever pulled (%s)", [kill_path_name(kill_path), case_file]),
		"path": "$.case.killPath",
	}
}

g_rehearsal contains finding if {
	kill_path_declared
	is_object(drill_doc)
	count(rehearsal_dates(kill_path_name(kill_path))) == 0
	finding := {
		"severity": "error",
		"rule": "killpath/never-rehearsed",
		"message": sprintf("the kill path '%s' is declared but the drill record holds no rehearsal of it: a kill path never rehearsed is a lever nobody has ever pulled (%s)", [kill_path_name(kill_path), drill_file]),
		"path": "$.case.killPath",
	}
}

g_rehearsal contains finding if {
	kill_path_stale
	finding := {
		"severity": "warning",
		"rule": "killpath/stale-rehearsal",
		"message": sprintf("the kill path '%s' was last rehearsed on %s, %s day(s) before the anchor date — beyond the drill record's %s-day staleness clock: a kill path rehearsed once and never again is a kill path that has drifted (%s)", [kill_path_name(kill_path), latest_rehearsal_date(kill_path_name(kill_path)), format_int(latest_rehearsal_age), format_int(max_staleness_days), drill_file]),
		"path": "$.case.killPath",
	}
}

# The kill path is rehearsed when the drill record holds at least one
# rehearsal of it dated on or before the anchor date.
kill_path_rehearsed if {
	kill_path_declared
	is_object(drill_doc)
	count(rehearsal_dates(kill_path_name(kill_path))) > 0
}

kill_path_stale if {
	kill_path_rehearsed
	lib.is_valid_date(today_date)
	latest_rehearsal_age > max_staleness_days
}

latest_rehearsal_age := lib.date_to_days(today_date) - lib.date_to_days(latest_rehearsal_date(kill_path_name(kill_path))) if {
	kill_path_rehearsed
	lib.is_valid_date(today_date)
}

case_declares_kill_path(name) if {
	is_object(kill_path)
	kill_path_name(kill_path) == name
}

# --- the posture cards ---------------------------------------------------------

# One row per judged item across the six areas of the case, in fixed
# area order, sorted by item inside each area. Only well-formed
# items render — a malformed row is a finding, not a card.
posture_cards := array.concat(request_policy_cards, array.concat(domain_cards, array.concat(cert_cards, array.concat(slo_cards, array.concat(audit_cards, kill_path_cards)))))

# Request policy: the default-deny that makes the allow list an
# allow list.
request_policy_cards := [card |
	is_object(request_policy)
	card := {
		"area": "request policy",
		"item": "default-deny",
		"verdict": request_policy_card_verdict,
		"detail": request_policy_card_detail,
	}
]

request_policy_card_verdict := "hardened" if {
	default_deny_declared
}

request_policy_card_verdict := "exposed" if {
	not default_deny_declared
}

request_policy_card_detail := sprintf("default-deny declared: the edge rejects by default and admits by exception (%s)", [case_file]) if {
	default_deny_declared
}

request_policy_card_detail := sprintf("no default-deny: every request rides an allow list that is not an allow list (%s)", [case_file]) if {
	not default_deny_declared
}

# Allowed domains: one row per declared pattern, concrete hosts and
# wildcards contained inside the zone held, too-broad patterns
# flagged for review.
domain_cards := sort([card |
	some d in domains
	lib.is_nonempty_string(domain_pattern(d))
	lib.is_nonempty_string(domain_intent(d))
	card := {
		"area": "allowed domains",
		"item": domain_pattern(d),
		"verdict": domain_card_verdict(d),
		"detail": domain_card_detail(d),
	}
])

domain_card_verdict(d) := "review" if {
	pattern_too_broad(domain_pattern(d))
}

domain_card_verdict(d) := "hardened" if {
	not pattern_too_broad(domain_pattern(d))
}

domain_card_detail(d) := sprintf("too broad: %s (%s)", [breadth_reason(domain_pattern(d)), case_file]) if {
	pattern_too_broad(domain_pattern(d))
}

domain_card_detail(d) := sprintf("a concrete host: the narrowest admit the platform can grant (%s)", [case_file]) if {
	not pattern_too_broad(domain_pattern(d))
	pattern_is_concrete(domain_pattern(d))
}

domain_card_detail(d) := sprintf("wildcard granted for '%s', contained inside the platform zone '%s' (%s)", [wildcard_suffix(domain_pattern(d)), zone, case_file]) if {
	not pattern_too_broad(domain_pattern(d))
	not pattern_is_concrete(domain_pattern(d))
	wildcard_in_zone(wildcard_suffix(domain_pattern(d)))
}

domain_card_detail(d) := sprintf("wildcard granted for '%s', but the case declares no zone to contain it (%s)", [wildcard_suffix(domain_pattern(d)), case_file]) if {
	not pattern_too_broad(domain_pattern(d))
	not pattern_is_concrete(domain_pattern(d))
	not wildcard_in_zone(wildcard_suffix(domain_pattern(d)))
}

# TLS certificates: one row per declared certificate, judged against
# its own rotation clock.
cert_cards := sort([card |
	some c in certs
	lib.is_nonempty_string(cert_serves(c))
	cert_window_valid(c)
	is_positive_integer(cert_rotate_by(c))
	lib.is_valid_date(today_date)
	card := {
		"area": "tls certificates",
		"item": cert_serves(c),
		"verdict": cert_card_verdict(c),
		"detail": cert_card_detail(c),
	}
])

cert_card_verdict(c) := "exposed" if {
	cert_days_left(c) < 0
}

cert_card_verdict(c) := "review" if {
	cert_days_left(c) >= 0
	cert_days_left(c) <= cert_rotate_by(c)
}

cert_card_verdict(c) := "hardened" if {
	cert_days_left(c) > cert_rotate_by(c)
}

cert_card_detail(c) := sprintf("expired on %s — %s day(s) before the anchor date (%s)", [cert_not_after(c), format_int(0 - cert_days_left(c)), case_file]) if {
	cert_days_left(c) < 0
}

cert_card_detail(c) := sprintf("inside its %s-day rotation window: %s day(s) left before %s (%s)", [format_int(cert_rotate_by(c)), format_int(cert_days_left(c)), cert_not_after(c), case_file]) if {
	cert_days_left(c) >= 0
	cert_days_left(c) <= cert_rotate_by(c)
}

cert_card_detail(c) := sprintf("valid until %s — %s day(s) beyond its rotation window (%s)", [cert_not_after(c), format_int(cert_days_left(c) - cert_rotate_by(c)), case_file]) if {
	cert_days_left(c) > cert_rotate_by(c)
}

# Service level objectives: one row per declared SLO, judged by the
# pager behind the target.
slo_cards := sort([card |
	some s in slos
	lib.is_nonempty_string(slo_name(s))
	lib.is_nonempty_string(slo_target(s))
	card := {
		"area": "service level objectives",
		"item": slo_name(s),
		"verdict": slo_card_verdict(s),
		"detail": slo_card_detail(s),
	}
])

slo_card_verdict(s) := "hardened" if {
	lib.is_nonempty_string(slo_pager(s))
}

slo_card_verdict(s) := "review" if {
	not lib.is_nonempty_string(slo_pager(s))
}

slo_card_detail(s) := sprintf("target %s with a pager behind it: a promise somebody swore to answer for (%s)", [slo_target(s), case_file]) if {
	lib.is_nonempty_string(slo_pager(s))
}

slo_card_detail(s) := sprintf("target %s with no pager: an SLO nobody pages is a promise nobody keeps (%s)", [slo_target(s), case_file]) if {
	not lib.is_nonempty_string(slo_pager(s))
}

# Audit coverage: one row per declared route class, judged by the
# logged classes the case swears to.
audit_cards := sort([card |
	some name in declared_route_classes
	card := {
		"area": "audit coverage",
		"item": name,
		"verdict": audit_card_verdict(name),
		"detail": audit_card_detail(name),
	}
])

declared_route_classes := sort({c |
	some r in routes
	c := route_class(r)
	lib.is_nonempty_string(c)
})

audit_card_verdict(name) := "hardened" if {
	class_logged(name)
}

audit_card_verdict(name) := "review" if {
	not class_logged(name)
}

audit_card_detail(name) := sprintf("route class logged at the edge: traffic the audit sees (%s)", [case_file]) if {
	class_logged(name)
}

audit_card_detail(name) := sprintf("unlogged route class: traffic the edge carries but the audit never sees (%s)", [case_file]) if {
	not class_logged(name)
}

# The kill path: one row, judged by its most recent rehearsal.
kill_path_cards := [card |
	is_object(kill_path)
	lib.is_nonempty_string(kill_path_name(kill_path))
	lib.is_nonempty_string(kill_path_effect(kill_path))
	card := {
		"area": "kill path",
		"item": kill_path_name(kill_path),
		"verdict": kill_path_card_verdict,
		"detail": kill_path_card_detail,
	}
]

kill_path_card_verdict := "exposed" if {
	not kill_path_rehearsed
}

kill_path_card_verdict := "review" if {
	kill_path_rehearsed
	kill_path_stale
}

kill_path_card_verdict := "hardened" if {
	kill_path_rehearsed
	not kill_path_stale
}

kill_path_card_detail := sprintf("no rehearsal on record: a kill path never rehearsed is a promise the platform has never kept (%s)", [drill_file]) if {
	not kill_path_rehearsed
}

kill_path_card_detail := sprintf("last rehearsed on %s — %s day(s) old, beyond the drill record's %s-day staleness clock (%s)", [latest_rehearsal_date(kill_path_name(kill_path)), format_int(latest_rehearsal_age), format_int(max_staleness_days), drill_file]) if {
	kill_path_rehearsed
	kill_path_stale
}

kill_path_card_detail := sprintf("rehearsed on %s, inside the drill record's %s-day staleness clock (%s)", [latest_rehearsal_date(kill_path_name(kill_path)), format_int(max_staleness_days), drill_file]) if {
	kill_path_rehearsed
	not kill_path_stale
}

# --- the gate verdict -----------------------------------------------------------

# Errors mean the posture is exposed — a break the platform can feel.
# Warnings mean review — the posture holds, but something is drifting.
# Neither means hardened.
gate_verdict(fs) := "exposed" if {
	count([f | f := fs[_]; f.severity == "error"]) > 0
}

gate_verdict(fs) := "review" if {
	count([f | f := fs[_]; f.severity == "error"]) == 0
	count([f | f := fs[_]; f.severity == "warning"]) > 0
}

gate_verdict(fs) := "hardened" if {
	count([f | f := fs[_]; f.severity == "error"]) == 0
	count([f | f := fs[_]; f.severity == "warning"]) == 0
}

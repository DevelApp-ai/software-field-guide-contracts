# The shared model for the ingress hardening conformance validator —
# The Software Field Guide, issue #82.
#
# Two documents enter: the INGRESS POSTURE CASE (the edge platform's
# posture as data — its DNS zone, the per-user allowed-domain patterns
# with the intent each grants, the request-time default-deny decision,
# the wildcard TLS certificates with their rotation clocks, the SLOs
# with their targets and pager links, the route classes with their
# audit coverage, and the kill path it promises it can pull) and the
# DRILL RECORD (the rehearsals that prove the kill path works — a
# drill without its evidence record is a rehearsal asserted, not
# evidenced). Posture is data until something judges it; the judge
# models a stated subset honestly (pattern form and zone containment,
# cert date windows and rotation clocks, SLO target and pager
# presence, route-class logging presence, drill staleness — not the
# full semantics of any real edge platform). Every accessor here
# guards its input before touching object fields — a malformed
# document must produce findings, never a WASM trap.
package ingress

import rego.v1

import data.ingress.lib

# --- the input documents ------------------------------------------------------

case_doc := v if {
	is_object(input)
	v := object.get(input, "case", null)
}

case_doc := null if not is_object(input)

drill_doc := v if {
	is_object(input)
	v := object.get(input, "drill", null)
}

drill_doc := null if not is_object(input)

# The injected clock, guarded: `today` arrives with the input and is
# never read from the wall. Accessed through this accessor so a
# malformed input (an array, a string) can never trap a builtin.
today_date := v if {
	is_object(input)
	v := object.get(input, "today", null)
}

today_date := null if not is_object(input)

# The file names the findings cite, guarded the same way: the CLI and
# the playground inject them so a finding names the document it came
# from. Absent, they degrade to the definite article — a finding still
# says which document offended, just not by file name.
case_file := v if {
	is_object(input)
	v := object.get(input, "caseFile", "the ingress posture case")
}

case_file := "the ingress posture case" if not is_object(input)

drill_file := v if {
	is_object(input)
	v := object.get(input, "drillFile", "the drill record")
}

drill_file := "the drill record" if not is_object(input)

# --- arrays, defensively -----------------------------------------------------

# A named array field of a document, or [] when the field is absent,
# malformed, or the document itself is not an object.
as_array(doc, key) := arr if {
	is_object(doc)
	arr := object.get(doc, key, [])
	is_array(arr)
}

as_array(doc, key) := [] if {
	is_object(doc)
	not is_array(object.get(doc, key, []))
}

as_array(doc, key) := [] if not is_object(doc)

# A positive integer — versions and rotation clocks are whole numbers.
is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# --- the posture case: the platform's zone ------------------------------------

# The DNS zone the platform owns: the containment boundary for
# wildcard patterns. A wildcard reaching outside the platform's own
# zone grants more than the platform meant to grant.
zone := v if {
	is_object(case_doc)
	v := object.get(case_doc, "zone", null)
}

zone := null if not is_object(case_doc)

zone_declared if lib.is_nonempty_string(zone)

# --- the posture case: the allowed-domain patterns -----------------------------

domains := [d | some d in as_array(case_doc, "domains"); is_object(d)]

domain_pattern(d) := object.get(d, "pattern", null)

domain_intent(d) := object.get(d, "intent", null)

# A pattern is concrete when it names one host and carries no
# wildcard at all — concrete hosts are judged by the routes and the
# request policy, not by breadth.
pattern_is_concrete(p) if {
	lib.is_nonempty_string(p)
	not contains(p, "*")
}

# The suffix a leading wildcard grants: everything after the "*.".
wildcard_suffix(p) := substring(p, 2, count(p) - 2) if {
	is_string(p)
	startswith(p, "*.")
}

# A suffix is deep enough when it names at least two labels —
# "*.com" grants a public suffix; "*.corp.example" names a branch.
suffix_deep_enough(s) if {
	count(split(s, ".")) >= 2
}

# A wildcard pattern is inside the platform's zone when its suffix is
# the zone itself or a branch of it. The zone must be declared first;
# an undeclared zone is its own finding, never a breadth miscount.
wildcard_in_zone(s) if {
	zone_declared
	s == zone
}

wildcard_in_zone(s) if {
	zone_declared
	endswith(s, sprintf(".%s", [zone]))
}

# The modeled breadth verdict of one pattern: the reason a pattern is
# too broad, for the message. Mutually exclusive bodies, most basic
# form first — a message never lists two reasons.
breadth_reason(p) := "the wildcard is not a leading '*.': a '*' may only grant a whole branch, never a name fragment" if {
	lib.is_nonempty_string(p)
	contains(p, "*")
	not startswith(p, "*.")
}

breadth_reason(p) := sprintf("the wildcard grants '%s', a suffix shallower than two labels", [wildcard_suffix(p)]) if {
	startswith(p, "*.")
	s := wildcard_suffix(p)
	not suffix_deep_enough(s)
}

breadth_reason(p) := sprintf("the wildcard grants '%s', outside the platform zone '%s' the case declares", [wildcard_suffix(p), zone]) if {
	startswith(p, "*.")
	s := wildcard_suffix(p)
	suffix_deep_enough(s)
	not wildcard_in_zone(s)
}

# A pattern is too broad when any modeled breadth condition fails.
pattern_too_broad(p) if breadth_reason(p)

# --- the posture case: the request-time policy --------------------------------

request_policy := v if {
	is_object(case_doc)
	v := object.get(case_doc, "requestPolicy", null)
}

request_policy := null if not is_object(case_doc)

# Default deny at request time: the router drops everything a route
# does not explicitly allow. Judged as a declared boolean — the
# validator reads the posture the case records, not the router.
default_deny_declared if {
	is_object(request_policy)
	object.get(request_policy, "defaultDeny", false) == true
}

# --- the posture case: the TLS certificates ------------------------------------

certs := [c | some c in as_array(case_doc, "certs"); is_object(c)]

cert_serves(c) := object.get(c, "serves", null)

cert_not_before(c) := object.get(c, "notBefore", null)

cert_not_after(c) := object.get(c, "notAfter", null)

cert_rotate_by(c) := object.get(c, "rotateByDays", null)

# A cert's window is well-formed when both dates are real and the
# window runs forward.
cert_window_valid(c) if {
	lib.is_valid_date(cert_not_before(c))
	lib.is_valid_date(cert_not_after(c))
	lib.date_to_days(cert_not_after(c)) - lib.date_to_days(cert_not_before(c)) > 0
}

# Days from the anchor date until the cert's window closes.
cert_days_left(c) := lib.date_to_days(cert_not_after(c)) - lib.date_to_days(today_date) if {
	lib.is_valid_date(today_date)
	lib.is_valid_date(cert_not_after(c))
}

# --- the posture case: the SLOs ------------------------------------------------

slos := [s | some s in as_array(case_doc, "slos"); is_object(s)]

slo_name(s) := object.get(s, "name", null)

slo_target(s) := object.get(s, "target", null)

slo_pager(s) := object.get(s, "pager", null)

# --- the posture case: the routes and their audit coverage ----------------------

routes := [r | some r in as_array(case_doc, "routes"); is_object(r)]

route_class(r) := object.get(r, "class", null)

logged_classes := [c | some c in as_array(case_doc, "loggedRouteClasses"); is_string(c)]

class_logged(name) if {
	some c in logged_classes
	c == name
}

class_declared(name) if {
	some r in routes
	route_class(r) == name
}

# --- the posture case: the kill path -------------------------------------------

kill_path := v if {
	is_object(case_doc)
	v := object.get(case_doc, "killPath", null)
}

kill_path := null if not is_object(case_doc)

kill_path_name(e) := object.get(e, "name", null)

kill_path_effect(e) := object.get(e, "effect", null)

kill_path_declared if {
	is_object(kill_path)
	lib.is_nonempty_string(kill_path_name(kill_path))
}

# --- the drill record: the rehearsals ------------------------------------------

drills := [d | some d in as_array(drill_doc, "drills"); is_object(d)]

drill_kill_path(d) := object.get(d, "killPath", null)

drill_drilled_on(d) := object.get(d, "drilledOn", null)

drill_evidence(d) := object.get(d, "evidence", null)

# The rehearsal-staleness clock, declared on the drill record and
# defaulted to the drill evidence harness's 180 days. A rehearsal
# older than the clock is a posture that once worked.
max_staleness_days := n if {
	is_object(drill_doc)
	n := object.get(drill_doc, "maxStalenessDays", 180)
	is_number(n)
}

max_staleness_days := 180 if {
	is_object(drill_doc)
	not is_number(object.get(drill_doc, "maxStalenessDays", 180))
}

max_staleness_days := 180 if not is_object(drill_doc)

# Days from the recorded drill date until the anchor date — the
# rehearsal's age. Both dates are validated before any arithmetic.
rehearsal_age(d) := lib.date_to_days(today_date) - lib.date_to_days(drill_drilled_on(d)) if {
	lib.is_valid_date(drill_drilled_on(d))
	lib.is_valid_date(today_date)
}

# The drill records that rehearse the case's declared kill path.
drills_for_kill_path(name) := [d |
	some d in drills
	drill_kill_path(d) == name
]

# The rehearsal dates that count: real dates, recorded on or before
# the anchor date. A drill dated in the future is its own finding —
# a rehearsal recorded in the future is a rehearsal that has not
# happened — and never softens the kill path's posture.
rehearsal_dates(name) := [d |
	some r in drills_for_kill_path(name)
	lib.is_valid_date(drill_drilled_on(r))
	lib.is_valid_date(today_date)
	drill_drilled_on(r) <= today_date
	d := drill_drilled_on(r)
]

# The most recent rehearsal of the declared kill path — the date the
# gate reads and the cards cite. ISO dates sort chronologically.
latest_rehearsal_date(name) := d if {
	dates := sort(rehearsal_dates(name))
	count(dates) > 0
	d := dates[count(dates) - 1]
}

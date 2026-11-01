# The ingress posture case validated alone — The Software Field Guide,
# issue #82.
#
# Every finding below judges ONE document: the posture case, the
# edge platform's security posture recorded as data. The case is
# the anonymized shape of a real developer-ingress platform: a DNS
# zone the platform owns, per-user allowed-domain patterns each with
# the intent that granted them, the request-time default-deny
# decision, the wildcard TLS certificates with their rotation
# clocks, the SLOs with their targets and pager links, the route
# classes with their audit coverage, and the kill path the platform
# promises it can pull. The validator models a stated subset
# honestly — pattern form and zone containment, cert date windows
# against the rotation clock, SLO target and pager presence,
# route-class logging presence — not the full semantics of any real
# edge platform.
package ingress

import rego.v1

import data.ingress.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_findings := ((((((((((((((((f_input_invalid | f_today_invalid) | f_case_missing) | f_case_stamps) | f_domains_shape) | f_domains_content) | f_request_policy) | f_certs_shape) | f_certs_content) | f_slos_shape) | f_slos_content) | f_routes_shape) | f_routes_content) | f_route_dupes) | f_audit_content) | f_audit_joins) | f_kill_path) | f_cert_clocks

# --- findings: the input and the clock -----------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the posture case as input.case",
		"path": "$",
	}
}

f_today_invalid contains finding if {
	is_object(input)
	not lib.is_valid_date(object.get(input, "today", null))
	finding := {
		"severity": "error",
		"rule": "input/today-invalid",
		"message": "today must be a real YYYY-MM-DD date — the clock is injected, never read",
		"path": "$.today",
	}
}

# --- findings: the case document -----------------------------------------------

f_case_missing contains finding if {
	not is_object(case_doc)
	finding := {
		"severity": "error",
		"rule": "case/missing",
		"message": "the ingress posture case is required: pass it as input.case",
		"path": "$.case",
	}
}

f_case_stamps contains finding if {
	is_object(case_doc)
	not is_positive_integer(object.get(case_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "case/version-required",
		"message": "the posture case must carry a version (a positive integer): posture is versioned like code",
		"path": "$.case.version",
	}
}

f_case_stamps contains finding if {
	is_object(case_doc)
	not lib.is_valid_date(object.get(case_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "case/reviewed-on-invalid",
		"message": "the posture case must carry reviewedOn as a real YYYY-MM-DD date",
		"path": "$.case.reviewedOn",
	}
}

f_case_stamps contains finding if {
	is_object(case_doc)
	lib.is_valid_date(object.get(case_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(case_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "case/reviewed-in-future",
		"message": "the posture case carries a reviewedOn date in the future",
		"path": "$.case.reviewedOn",
	}
}

f_case_stamps contains finding if {
	is_object(case_doc)
	lib.is_valid_date(object.get(case_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(case_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "case/reviewed-stale",
		"message": "the posture case was reviewed more than 365 days before today: this posture says nothing about the platform that changed since",
		"path": "$.case.reviewedOn",
	}
}

f_case_stamps contains finding if {
	is_object(case_doc)
	not lib.is_nonempty_string(object.get(case_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "case/owner-required",
		"message": "the posture case must name an owner: a posture file with an owner and a review cadence is the discipline",
		"path": "$.case.owner",
	}
}

f_case_stamps contains finding if {
	is_object(case_doc)
	not lib.is_nonempty_string(zone)
	finding := {
		"severity": "error",
		"rule": "case/zone-required",
		"message": sprintf("the posture case must declare the platform's DNS zone: the zone is the containment boundary — a wildcard reaching outside it grants more than the platform meant to grant (%s)", [case_file]),
		"path": "$.case.zone",
	}
}

# --- findings: the allowed-domain patterns -------------------------------------

f_domains_shape contains finding if {
	is_object(case_doc)
	not is_array(object.get(case_doc, "domains", null))
	finding := {
		"severity": "error",
		"rule": "domains/must-be-array",
		"message": "the posture case's domains must be an array of {pattern, intent} rows",
		"path": "$.case.domains",
	}
}

f_domains_shape contains finding if {
	some d in as_array(case_doc, "domains")
	not is_object(d)
	finding := {
		"severity": "error",
		"rule": "domains/row-must-be-object",
		"message": "every domains row must be an object with pattern and intent",
		"path": "$.case.domains",
	}
}

f_domains_content contains finding if {
	some d in domains
	not lib.is_nonempty_string(domain_pattern(d))
	finding := {
		"severity": "error",
		"rule": "domain/pattern-required",
		"message": "every allowed domain must carry its pattern: a granted domain without its pattern is a grant nobody can audit",
		"path": "$.case.domains",
	}
}

f_domains_content contains finding if {
	some d in domains
	lib.is_nonempty_string(domain_pattern(d))
	not lib.is_nonempty_string(domain_intent(d))
	finding := {
		"severity": "error",
		"rule": "domain/intent-required",
		"message": sprintf("the pattern '%s' must carry the intent that granted it: a grant without its recorded intent cannot be judged against it (%s)", [domain_pattern(d), case_file]),
		"path": "$.case.domains",
	}
}

f_domains_content contains finding if {
	some d in domains
	lib.is_nonempty_string(domain_pattern(d))
	lib.is_nonempty_string(domain_intent(d))
	pattern_too_broad(domain_pattern(d))
	finding := {
		"severity": "error",
		"rule": "domain/too-broad",
		"message": sprintf("the pattern '%s' is broader than the platform should grant (%s): %s — a wildcard that outgrew its intent is the posture regression nobody notices until it is exploited", [domain_pattern(d), case_file, breadth_reason(domain_pattern(d))]),
		"path": "$.case.domains",
	}
}

# --- findings: the request-time policy ------------------------------------------

f_request_policy contains finding if {
	is_object(case_doc)
	not is_object(request_policy)
	finding := {
		"severity": "error",
		"rule": "requestpolicy/required",
		"message": "the posture case must record its request-time policy: default deny is a decision, and a decision that was never recorded is a decision nobody can verify",
		"path": "$.case.requestPolicy",
	}
}

f_request_policy contains finding if {
	is_object(case_doc)
	is_object(request_policy)
	object.get(request_policy, "defaultDeny", false) != true
	finding := {
		"severity": "error",
		"rule": "requestpolicy/default-deny-required",
		"message": sprintf("the request-time policy must declare default deny: with the default anything but deny, every route not explicitly blocked is implicitly allowed — posture by omission (%s)", [case_file]),
		"path": "$.case.requestPolicy.defaultDeny",
	}
}

f_request_policy contains finding if {
	is_object(case_doc)
	is_object(request_policy)
	not lib.is_nonempty_string(object.get(request_policy, "decision", null))
	finding := {
		"severity": "error",
		"rule": "requestpolicy/decision-required",
		"message": "the request-time policy must record its decision in words: the deny rule the edge actually applies is the one its operators can rehearse",
		"path": "$.case.requestPolicy.decision",
	}
}

# --- findings: the TLS certificates --------------------------------------------

f_certs_shape contains finding if {
	is_object(case_doc)
	not is_array(object.get(case_doc, "certs", null))
	finding := {
		"severity": "error",
		"rule": "certs/must-be-array",
		"message": "the posture case's certs must be an array of {serves, notBefore, notAfter, rotateByDays} rows",
		"path": "$.case.certs",
	}
}

f_certs_shape contains finding if {
	some c in as_array(case_doc, "certs")
	not is_object(c)
	finding := {
		"severity": "error",
		"rule": "certs/row-must-be-object",
		"message": "every certs row must be an object naming the host it serves and its window",
		"path": "$.case.certs",
	}
}

f_certs_content contains finding if {
	some c in certs
	not lib.is_nonempty_string(cert_serves(c))
	finding := {
		"severity": "error",
		"rule": "cert/serves-required",
		"message": "every certificate must name the host it serves: a cert nobody can attribute is a window nobody watches",
		"path": "$.case.certs",
	}
}

f_certs_content contains finding if {
	some c in certs
	not lib.is_valid_date(cert_not_before(c))
	finding := {
		"severity": "error",
		"rule": "cert/not-before-invalid",
		"message": "every certificate window must carry notBefore as a real YYYY-MM-DD date",
		"path": "$.case.certs",
	}
}

f_certs_content contains finding if {
	some c in certs
	not lib.is_valid_date(cert_not_after(c))
	finding := {
		"severity": "error",
		"rule": "cert/not-after-invalid",
		"message": "every certificate window must carry notAfter as a real YYYY-MM-DD date",
		"path": "$.case.certs",
	}
}

f_certs_content contains finding if {
	some c in certs
	lib.is_valid_date(cert_not_before(c))
	lib.is_valid_date(cert_not_after(c))
	not cert_window_valid(c)
	finding := {
		"severity": "error",
		"rule": "cert/window-invalid",
		"message": sprintf("the certificate serving '%s' carries a window that does not run forward: notAfter must fall after notBefore", [cert_serves(c)]),
		"path": "$.case.certs",
	}
}

f_certs_content contains finding if {
	some c in certs
	not is_positive_integer(cert_rotate_by(c))
	finding := {
		"severity": "error",
		"rule": "cert/rotate-by-required",
		"message": "every certificate must declare its rotation clock in days (a positive integer): the rotation window is what turns an expiry into a routine, not an incident",
		"path": "$.case.certs",
	}
}

f_cert_clocks contains finding if {
	some c in certs
	cert_window_valid(c)
	is_positive_integer(cert_rotate_by(c))
	lib.is_valid_date(today_date)
	cert_days_left(c) < 0
	finding := {
		"severity": "error",
		"rule": "cert/expired",
		"message": sprintf("the certificate serving '%s' expired on %s (%s days before the anchor date): an expired cert at the edge is an outage or a bypass waiting to happen (%s)", [cert_serves(c), cert_not_after(c), format_int(0 - cert_days_left(c)), case_file]),
		"path": "$.case.certs",
	}
}

f_cert_clocks contains finding if {
	some c in certs
	cert_window_valid(c)
	is_positive_integer(cert_rotate_by(c))
	lib.is_valid_date(today_date)
	cert_days_left(c) >= 0
	cert_days_left(c) <= cert_rotate_by(c)
	finding := {
		"severity": "warning",
		"rule": "cert/near-expiry",
		"message": sprintf("the certificate serving '%s' expires on %s — inside its %s-day rotation window, %s day(s) left: the cert that rotates late is the cert that expires (%s)", [cert_serves(c), cert_not_after(c), format_int(cert_rotate_by(c)), format_int(cert_days_left(c)), case_file]),
		"path": "$.case.certs",
	}
}

# --- findings: the SLOs ---------------------------------------------------------

f_slos_shape contains finding if {
	is_object(case_doc)
	not is_array(object.get(case_doc, "slos", null))
	finding := {
		"severity": "error",
		"rule": "slos/must-be-array",
		"message": "the posture case's slos must be an array of {name, target, pager} rows",
		"path": "$.case.slos",
	}
}

f_slos_shape contains finding if {
	some s in as_array(case_doc, "slos")
	not is_object(s)
	finding := {
		"severity": "error",
		"rule": "slos/row-must-be-object",
		"message": "every slos row must be an object naming the objective it tracks",
		"path": "$.case.slos",
	}
}

f_slos_content contains finding if {
	some s in slos
	not lib.is_nonempty_string(slo_name(s))
	finding := {
		"severity": "error",
		"rule": "slo/name-required",
		"message": "every SLO must be named: an objective nobody can name is an objective nobody holds",
		"path": "$.case.slos",
	}
}

f_slos_content contains finding if {
	some s in slos
	lib.is_nonempty_string(slo_name(s))
	not lib.is_nonempty_string(slo_target(s))
	finding := {
		"severity": "error",
		"rule": "slo/target-required",
		"message": sprintf("the SLO '%s' must carry its target: an SLO without a target is a hope, not an objective (%s)", [slo_name(s), case_file]),
		"path": "$.case.slos",
	}
}

f_slos_content contains finding if {
	some s in slos
	lib.is_nonempty_string(slo_name(s))
	lib.is_nonempty_string(slo_target(s))
	not lib.is_nonempty_string(slo_pager(s))
	finding := {
		"severity": "error",
		"rule": "slo/pager-required",
		"message": sprintf("the SLO '%s' must carry its pager link: an SLO that pages nobody is a dashboard, not a gate (%s)", [slo_name(s), case_file]),
		"path": "$.case.slos",
	}
}

# --- findings: the routes and their audit coverage ------------------------------

f_routes_shape contains finding if {
	is_object(case_doc)
	not is_array(object.get(case_doc, "routes", null))
	finding := {
		"severity": "error",
		"rule": "routes/must-be-array",
		"message": "the posture case's routes must be an array of {class} rows",
		"path": "$.case.routes",
	}
}

f_routes_shape contains finding if {
	some r in as_array(case_doc, "routes")
	not is_object(r)
	finding := {
		"severity": "error",
		"rule": "routes/row-must-be-object",
		"message": "every routes row must be an object naming its route class",
		"path": "$.case.routes",
	}
}

f_routes_content contains finding if {
	some r in routes
	not lib.is_nonempty_string(route_class(r))
	finding := {
		"severity": "error",
		"rule": "route/class-required",
		"message": "every route must name its class: audit coverage is judged per class, and a route without one is a route nobody can account for",
		"path": "$.case.routes",
	}
}

f_route_dupes contains finding if {
	dupes := sort({name |
		some r in routes
		name := route_class(r)
		lib.is_nonempty_string(name)
		count([x | some x in routes; route_class(x) == name]) > 1
	})
	some dup in dupes
	finding := {
		"severity": "error",
		"rule": "route/class-duplicate",
		"message": sprintf("the route class '%s' is declared more than once: duplicated coverage is double-counted coverage", [dup]),
		"path": "$.case.routes",
	}
}

f_audit_content contains finding if {
	is_object(case_doc)
	not is_array(object.get(case_doc, "loggedRouteClasses", null))
	finding := {
		"severity": "error",
		"rule": "audit/logged-required",
		"message": "the posture case must declare its loggedRouteClasses: the classes whose traffic is logged are the platform's audit coverage, and coverage nobody declared is coverage nobody verified",
		"path": "$.case.loggedRouteClasses",
	}
}

f_audit_joins contains finding if {
	some r in routes
	lib.is_nonempty_string(route_class(r))
	count([x | some x in as_array(case_doc, "loggedRouteClasses"); x == route_class(r)]) > 1
	finding := {
		"severity": "error",
		"rule": "audit/logged-duplicate",
		"message": sprintf("the loggedRouteClasses list names '%s' more than once: double-listed coverage is coverage someone padded", [route_class(r)]),
		"path": "$.case.loggedRouteClasses",
	}
}

f_audit_joins contains finding if {
	is_object(case_doc)
	is_array(object.get(case_doc, "loggedRouteClasses", null))
	some r in routes
	lib.is_nonempty_string(route_class(r))
	not class_logged(route_class(r))
	finding := {
		"severity": "error",
		"rule": "audit/class-unlogged",
		"message": sprintf("the route class '%s' is not in loggedRouteClasses: traffic that crosses the edge unlogged is an audit-coverage gap — what the platform cannot see, it cannot investigate (%s)", [route_class(r), case_file]),
		"path": "$.case.loggedRouteClasses",
	}
}

f_audit_joins contains finding if {
	is_object(case_doc)
	is_array(object.get(case_doc, "loggedRouteClasses", null))
	some c in as_array(case_doc, "loggedRouteClasses")
	is_string(c)
	not class_declared(c)
	finding := {
		"severity": "error",
		"rule": "audit/unknown-class-logged",
		"message": sprintf("the loggedRouteClasses list names '%s', a class no route declares: claimed coverage that covers nothing is worse than none — the join is verified both ways (%s)", [c, case_file]),
		"path": "$.case.loggedRouteClasses",
	}
}

# --- findings: the kill path ----------------------------------------------------

f_kill_path contains finding if {
	is_object(case_doc)
	not is_object(kill_path)
	finding := {
		"severity": "error",
		"rule": "killpath/required",
		"message": "the posture case must declare its kill path: a platform that cannot name how it fails closed is a platform that will fail open",
		"path": "$.case.killPath",
	}
}

f_kill_path contains finding if {
	is_object(kill_path)
	not lib.is_nonempty_string(kill_path_name(kill_path))
	finding := {
		"severity": "error",
		"rule": "killpath/name-required",
		"message": "the kill path must be named: the drill record cites the path by name, and a path that cannot be cited cannot be rehearsed",
		"path": "$.case.killPath.name",
	}
}

f_kill_path contains finding if {
	is_object(kill_path)
	lib.is_nonempty_string(kill_path_name(kill_path))
	not lib.is_nonempty_string(kill_path_effect(kill_path))
	finding := {
		"severity": "error",
		"rule": "killpath/effect-required",
		"message": "the kill path must record its effect in words: the effect is what the rehearsal verifies, and an effect nobody wrote down is an effect nobody checked",
		"path": "$.case.killPath.effect",
	}
}

# --- local helpers -------------------------------------------------------------

format_int(n) := sprintf("%d", [n])

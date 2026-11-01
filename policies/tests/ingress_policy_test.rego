package ingress.policy_test

import rego.v1

import data.ingress

import data.ingress.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

# --- the control: one zoned edge, everything contained --------------------------

test_control_case_valid if {
	r := ingress.validate with input as fixture.validate_input(fixture.case)
	r.valid == true
	count(r.findings) == 0
}

test_validate_answers_in_the_stable_shape if {
	r := ingress.validate with input as fixture.validate_input(fixture.case)
	object.keys(r) == {"findings", "valid"}
}

test_input_must_be_object if {
	r := ingress.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := ingress.validate with input as {"case": fixture.case, "today": "2026-13-01"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_case_missing if {
	r := ingress.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["case/missing"]
}

# --- the case's own stamps ------------------------------------------------------

test_version_required if {
	c := fixture.with_field(fixture.case, {"version": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["case/version-required"]
}

test_reviewed_on_invalid if {
	c := fixture.with_field(fixture.case, {"reviewedOn": "10/01/2026"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["case/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	c := fixture.with_field(fixture.case, {"reviewedOn": "2026-12-01"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["case/reviewed-in-future"]
}

test_reviewed_stale if {
	c := fixture.with_field(fixture.case, {"reviewedOn": "2024-10-01"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["case/reviewed-stale"]
}

test_owner_required if {
	c := fixture.with_field(fixture.case, {"owner": ""})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["case/owner-required"]
}

test_zone_required if {
	c := fixture.with_field(fixture.case, {"zone": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["case/zone-required"]
}

# --- the allowed domains -------------------------------------------------------

test_domains_must_be_array if {
	c := fixture.with_field(fixture.case, {"domains": "partner.example.com"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["domains/must-be-array"]
}

test_domain_row_must_be_object if {
	c := fixture.with_field(fixture.case, {"domains": ["partner.example.com"]})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["domains/row-must-be-object"]
}

test_domain_pattern_required if {
	c := fixture.with_domain_field(fixture.case, "partner.example.com", {"pattern": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["domain/pattern-required"]
}

test_domain_intent_required if {
	c := fixture.with_domain_field(fixture.case, "*.dev.internal", {"intent": ""})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["domain/intent-required"]
}

test_wildcard_outside_the_zone_is_too_broad if {
	c := fixture.with_domain_field(fixture.case, "*.dev.internal", {"pattern": "*.example.com"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["domain/too-broad"]
}

test_shallow_wildcard_suffix_is_too_broad if {
	c := fixture.with_domain_field(fixture.case, "*.dev.internal", {"pattern": "*.com"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["domain/too-broad"]
}

test_non_leading_wildcard_is_too_broad if {
	c := fixture.with_domain_field(fixture.case, "*.dev.internal", {"pattern": "app-*.dev.internal"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["domain/too-broad"]
}

test_wildcard_inside_the_zone_is_not_flagged if {
	r := ingress.validate with input as fixture.validate_input(fixture.case)
	not error_rules(r)["domain/too-broad"]
}

# --- the request policy --------------------------------------------------------

test_request_policy_required if {
	c := fixture.with_field(fixture.case, {"requestPolicy": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["requestpolicy/required"]
}

test_default_deny_required if {
	c := fixture.with_field(fixture.case, {"requestPolicy": {"defaultDeny": false, "decision": "admit everything"}})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["requestpolicy/default-deny-required"]
}

test_decision_required if {
	c := fixture.with_field(fixture.case, {"requestPolicy": {"defaultDeny": true}})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["requestpolicy/decision-required"]
}

# --- the TLS certificates ------------------------------------------------------

test_certs_must_be_array if {
	c := fixture.with_field(fixture.case, {"certs": "edge.dev.internal"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["certs/must-be-array"]
}

test_cert_row_must_be_object if {
	c := fixture.with_field(fixture.case, {"certs": ["edge.dev.internal"]})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["certs/row-must-be-object"]
}

test_cert_serves_required if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"serves": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["cert/serves-required"]
}

test_not_before_invalid if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"notBefore": "01/08/2026"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["cert/not-before-invalid"]
}

test_not_after_invalid if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"notAfter": "2027-13-01"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["cert/not-after-invalid"]
}

test_cert_window_invalid if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"notBefore": "2026-09-01", "notAfter": "2026-08-01"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["cert/window-invalid"]
}

test_rotate_by_required if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"rotateByDays": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["cert/rotate-by-required"]
}

test_expired_cert if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"notAfter": "2026-09-30"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["cert/expired"]
}

test_near_expiry_cert_flags_honestly if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"notAfter": "2026-11-10"})
	r := ingress.validate with input as fixture.validate_input(c)
	r.valid == true
	warning_rules(r)["cert/near-expiry"]
	not error_rules(r)["cert/near-expiry"]
}

test_near_expiry_boundary_expiring_today_flags if {
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"notAfter": fixture.today})
	r := ingress.validate with input as fixture.validate_input(c)
	r.valid == true
	warning_rules(r)["cert/near-expiry"]
}

test_rotation_boundary_not_flagged if {
	# ninety-one days left against a ninety-day clock: outside the
	# rotation window, hardened.
	c := fixture.with_cert_field(fixture.case, "edge.dev.internal", {"notAfter": "2027-01-19", "rotateByDays": 90})
	r := ingress.validate with input as fixture.validate_input(c)
	not warning_rules(r)["cert/near-expiry"]
	not error_rules(r)["cert/expired"]
}

# --- the service level objectives ----------------------------------------------

test_slos_must_be_array if {
	c := fixture.with_field(fixture.case, {"slos": "edge availability"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["slos/must-be-array"]
}

test_slo_row_must_be_object if {
	c := fixture.with_field(fixture.case, {"slos": ["edge availability"]})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["slos/row-must-be-object"]
}

test_slo_name_required if {
	c := fixture.with_slo_field(fixture.case, "edge availability", {"name": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["slo/name-required"]
}

test_slo_target_required if {
	c := fixture.with_slo_field(fixture.case, "edge availability", {"target": ""})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["slo/target-required"]
}

test_slo_pager_required if {
	c := fixture.with_slo_field(fixture.case, "edge availability", {"pager": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["slo/pager-required"]
}

# --- the routes and the audit coverage -----------------------------------------

test_routes_must_be_array if {
	c := fixture.with_field(fixture.case, {"routes": "developer-app"})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["routes/must-be-array"]
}

test_route_row_must_be_object if {
	c := fixture.with_field(fixture.case, {"routes": ["developer-app"]})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["routes/row-must-be-object"]
}

test_route_class_required if {
	c := fixture.with_field(fixture.case, {"routes": [{"class": "developer-app"}, {"class": null}]})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["route/class-required"]
}

test_route_class_duplicate if {
	c := fixture.with_field(fixture.case, {"routes": [{"class": "developer-app"}, {"class": "developer-app"}]})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["route/class-duplicate"]
}

test_audit_logged_required if {
	c := fixture.with_field(fixture.case, {"loggedRouteClasses": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["audit/logged-required"]
}

test_unlogged_route_class if {
	c := fixture.with_field(fixture.case, {"loggedRouteClasses": ["developer-app", "health-check"]})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["audit/class-unlogged"]
}

test_unknown_class_logged if {
	c := fixture.with_field(fixture.case, {"loggedRouteClasses": ["developer-app", "partner-api", "health-check", "admin-console"]})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["audit/unknown-class-logged"]
}

test_logged_duplicate if {
	c := fixture.with_field(fixture.case, {"loggedRouteClasses": ["developer-app", "developer-app", "partner-api", "health-check"]})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["audit/logged-duplicate"]
}

# --- the kill path -----------------------------------------------------------

test_kill_path_required if {
	c := fixture.with_field(fixture.case, {"killPath": null})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["killpath/required"]
}

test_kill_path_name_required if {
	c := fixture.with_field(fixture.case, {"killPath": {"effect": "the edge denies all ingress"}})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["killpath/name-required"]
}

test_kill_path_effect_required if {
	c := fixture.with_field(fixture.case, {"killPath": {"name": "seal-edge"}})
	r := ingress.validate with input as fixture.validate_input(c)
	not r.valid
	error_rules(r)["killpath/effect-required"]
}

# --- lib parity: the date helpers are a verbatim copy of the estate lib ------

test_epoch_is_day_zero if {
	ingress.lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	ingress.lib.date_to_days("2026-10-20") - ingress.lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not ingress.lib.is_valid_date("2026-02-30")
}

package estate.seam_test

import rego.v1

import data.estate.seam

today := "2026-10-20"

valid_contract := {
	"seam": "checkout-web-tier",
	"enclave": "checkout",
	"entry": "Internet-facing endpoint behind the edge gateway; mTLS terminates at the gateway and requests continue with a forwarded identity token",
	"decision": "Default deny at the gateway; each route is an explicit allow",
	"monitoring": "Gateway access logs, p99 latency metric, alert on 5xx rate",
	"blastRadius": "A spoofed session can read one customer's cart",
	"killPath": "Drop the gateway route; the edge fails closed",
	"lastRehearsed": "2026-08-30",
	"reviewDate": "2026-12-01",
}

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

test_valid_contract_passes if {
	r := seam.validate with input as {"contract": valid_contract, "today": today}
	r.valid == true
	count(r.findings) == 0
}

test_missing_kill_path if {
	r := seam.validate with input as {"contract": object.remove(valid_contract, ["killPath"]), "today": today}
	not r.valid
	error_rules(r)["contract/required-field-missing"]
}

test_missing_monitoring if {
	r := seam.validate with input as {"contract": object.remove(valid_contract, ["monitoring"]), "today": today}
	not r.valid
	error_rules(r)["contract/required-field-missing"]
}

test_entry_without_identity_mechanism if {
	c := object.union(valid_contract, {"entry": "Requests arrive at the storefront endpoint"})
	r := seam.validate with input as {"contract": c, "today": today}
	r.valid == true
	warning_rules(r)["contract/entry-no-identity-mechanism"]
}

test_decision_without_deny if {
	c := object.union(valid_contract, {"decision": "Only the storefront service may call through"})
	r := seam.validate with input as {"contract": c, "today": today}
	r.valid == true
	warning_rules(r)["contract/decision-no-deny-rule"]
}

test_monitoring_without_observation if {
	c := object.union(valid_contract, {"monitoring": "The platform team keeps an eye on it"})
	r := seam.validate with input as {"contract": c, "today": today}
	r.valid == true
	warning_rules(r)["contract/monitoring-not-stated"]
}

test_all_keyword_warnings_still_valid if {
	c := object.union(valid_contract, {
		"entry": "Requests arrive at the storefront endpoint",
		"decision": "Only the storefront service may call through",
		"monitoring": "The platform team keeps an eye on it",
	})
	r := seam.validate with input as {"contract": c, "today": today}
	r.valid == true
	count(r.findings) == 3
	count(warning_rules(r)) == 3
}

test_last_rehearsed_bad_format if {
	r := seam.validate with input as {"contract": object.union(valid_contract, {"lastRehearsed": "August"}), "today": today}
	not r.valid
	error_rules(r)["contract/last-rehearsed-invalid"]
}

test_last_rehearsed_in_future if {
	r := seam.validate with input as {"contract": object.union(valid_contract, {"lastRehearsed": "2026-10-21"}), "today": today}
	not r.valid
	error_rules(r)["contract/last-rehearsed-in-future"]
}

test_last_rehearsed_stale if {
	r := seam.validate with input as {"contract": object.union(valid_contract, {"lastRehearsed": "2026-04-01"}), "today": today}
	not r.valid
	error_rules(r)["contract/last-rehearsed-stale"]
}

test_last_rehearsed_exactly_180_days_old_passes if {
	r := seam.validate with input as {"contract": object.union(valid_contract, {"lastRehearsed": "2026-04-23"}), "today": today}
	r.valid == true
}

test_review_date_bad_format if {
	r := seam.validate with input as {"contract": object.union(valid_contract, {"reviewDate": "2026-12-1"}), "today": today}
	not r.valid
	error_rules(r)["contract/review-date-invalid"]
}

test_review_date_overdue if {
	r := seam.validate with input as {"contract": object.union(valid_contract, {"reviewDate": "2026-10-19"}), "today": today}
	not r.valid
	error_rules(r)["contract/review-overdue"]
}

test_review_date_today_passes if {
	r := seam.validate with input as {"contract": object.union(valid_contract, {"reviewDate": "2026-10-20"}), "today": today}
	r.valid == true
}

test_input_must_be_object if {
	r := seam.validate with input as "seam"
	not r.valid
	r.findings[0].rule == "input/invalid"
}

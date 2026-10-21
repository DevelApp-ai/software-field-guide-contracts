package estate.cross_test

import rego.v1

import data.estate.cross

checkout_enclave := {
	"enclave": "checkout",
	"owner": "Checkout team",
	"trustedIdentityPlanes": [{"plane": "customer-web", "provider": "opaque-token"}],
	"borderInventory": ["checkout-web-tier"],
	"blastRadius": {
		"data": "Cart contents and customer profile cache",
		"statedLimit": "Cart rows for one storefront, one hour",
	},
	"reviewedOn": "2026-09-15",
}

payments_enclave := {
	"enclave": "payments",
	"owner": "Payments team",
	"trustedIdentityPlanes": [{"plane": "internal-services", "provider": "mtls-svid"}],
	"borderInventory": ["payments-3ds-redirect"],
	"blastRadius": {
		"data": "Charge attempts and masked card references",
		"statedLimit": "One payment provider account, 24 hours",
	},
	"reviewedOn": "2026-09-02",
}

checkout_web_tier := {
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

payments_3ds := {
	"seam": "payments-3ds-redirect",
	"enclave": "payments",
	"entry": "Browser redirect back from the 3-D Secure provider; the callback is authenticated with a signed token tied to the original auth challenge",
	"decision": "Verify the callback signature and deny unverified callbacks",
	"monitoring": "Every callback logged and counted; alert on verification failure rate",
	"blastRadius": "A forged callback could mark a charge as completed",
	"killPath": "Disable the callback route; pending charges fail closed",
	"lastRehearsed": "2026-09-10",
	"reviewDate": "2026-11-15",
}

valid_bundle := {
	"enclaves": [checkout_enclave, payments_enclave],
	"seams": [checkout_web_tier, payments_3ds],
}

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

test_valid_bundle_passes if {
	r := cross.validate with input as valid_bundle
	r.valid == true
	count(r.findings) == 0
}

test_missing_enclaves_array if {
	r := cross.validate with input as object.remove(valid_bundle, ["enclaves"])
	not r.valid
	error_rules(r)["bundle/enclaves-must-be-array"]
}

test_missing_seams_array if {
	r := cross.validate with input as object.remove(valid_bundle, ["seams"])
	not r.valid
	error_rules(r)["bundle/seams-must-be-array"]
}

test_input_must_be_object if {
	r := cross.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_border_seam_without_contract if {
	c := object.union(payments_enclave, {"borderInventory": ["payments-3ds-redirect", "payments-payout-batch"]})
	r := cross.validate with input as {"enclaves": [checkout_enclave, c], "seams": [checkout_web_tier, payments_3ds]}
	not r.valid
	some f in r.findings
	f.rule == "bundle/border-seam-without-contract"
	f.path == "$.enclaves[1].borderInventory[1]"
}

test_seam_with_unknown_enclave if {
	c := object.union(payments_3ds, {"enclave": "billing"})
	r := cross.validate with input as {"enclaves": [checkout_enclave, payments_enclave], "seams": [checkout_web_tier, c]}
	not r.valid
	some f in r.findings
	f.rule == "bundle/seam-enclave-unknown"
	f.path == "$.seams[1].enclave"
}

test_duplicate_enclave_names_reported_once if {
	r := cross.validate with input as {"enclaves": [checkout_enclave, checkout_enclave], "seams": [checkout_web_tier]}
	not r.valid
	count([f | some f in r.findings; f.rule == "bundle/duplicate-enclave-name"]) == 1
}

test_duplicate_enclave_names_three_copies_still_one_finding if {
	r := cross.validate with input as {"enclaves": [checkout_enclave, checkout_enclave, checkout_enclave], "seams": []}
	not r.valid
	count([f | some f in r.findings; f.rule == "bundle/duplicate-enclave-name"]) == 1
}

test_duplicate_seam_names_reported_once if {
	r := cross.validate with input as {"enclaves": [checkout_enclave], "seams": [checkout_web_tier, checkout_web_tier]}
	not r.valid
	count([f | some f in r.findings; f.rule == "bundle/duplicate-seam-name"]) == 1
}

test_orphan_seam_contract_is_a_warning if {
	orphan := object.union(checkout_web_tier, {"seam": "checkout-forgotten-seam"})
	r := cross.validate with input as {"enclaves": [checkout_enclave], "seams": [checkout_web_tier, orphan]}
	r.valid == true
	warning_rules(r)["bundle/seam-not-in-inventory"]
}

test_per_contract_fields_are_not_judged_here if {
	sloppy := object.remove(payments_3ds, ["killPath"])
	r := cross.validate with input as {"enclaves": [checkout_enclave, payments_enclave], "seams": [checkout_web_tier, sloppy]}
	r.valid == true
}

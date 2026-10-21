package estate.enclave_test

import rego.v1

import data.estate.enclave

today := "2026-10-20"

valid_contract := {
	"enclave": "checkout",
	"owner": "Checkout team",
	"trustedIdentityPlanes": [
		{"plane": "customer-web", "provider": "opaque-token"},
		{"plane": "internal-services", "provider": "mtls-svid"},
	],
	"borderInventory": ["checkout-web-tier", "checkout-payment-redirect"],
	"blastRadius": {
		"data": "Cart contents and customer profile cache",
		"statedLimit": "Cart rows for one storefront, one hour",
	},
	"reviewedOn": "2026-09-15",
}

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

warning_rules(r) := {f.rule | some f in r.findings; f.severity == "warning"}

test_valid_contract_passes if {
	r := enclave.validate with input as {"contract": valid_contract, "today": today}
	r.valid == true
	count(r.findings) == 0
}

test_missing_contract if {
	r := enclave.validate with input as {"today": today}
	not r.valid
	error_rules(r)["contract/missing"]
}

test_input_must_be_object if {
	r := enclave.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_invalid_today if {
	r := enclave.validate with input as {"contract": valid_contract, "today": "yesterday"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_missing_enclave_name if {
	r := enclave.validate with input as {"contract": object.remove(valid_contract, ["enclave"]), "today": today}
	not r.valid
	error_rules(r)["contract/required-field-missing"]
}

test_whitespace_owner if {
	r := enclave.validate with input as {"contract": object.union(valid_contract, {"owner": "   "}), "today": today}
	not r.valid
	error_rules(r)["contract/required-field-missing"]
}

test_missing_identity_planes if {
	r := enclave.validate with input as {"contract": object.remove(valid_contract, ["trustedIdentityPlanes"]), "today": today}
	not r.valid
	error_rules(r)["contract/trusted-identity-planes-must-be-array"]
}

test_empty_identity_planes if {
	r := enclave.validate with input as {"contract": object.union(valid_contract, {"trustedIdentityPlanes": []}), "today": today}
	not r.valid
	error_rules(r)["contract/trusted-identity-planes-required"]
}

test_identity_plane_missing_provider if {
	c := object.union(valid_contract, {"trustedIdentityPlanes": [{"plane": "customer-web"}]})
	r := enclave.validate with input as {"contract": c, "today": today}
	not r.valid
	error_rules(r)["contract/identity-plane-field-required"]
	some f in r.findings
	f.path == "$.contract.trustedIdentityPlanes[0].provider"
}

test_identity_plane_not_an_object if {
	c := object.union(valid_contract, {"trustedIdentityPlanes": ["customer-web"]})
	r := enclave.validate with input as {"contract": c, "today": today}
	not r.valid
	error_rules(r)["contract/identity-plane-must-be-object"]
}

test_missing_border_inventory if {
	r := enclave.validate with input as {"contract": object.remove(valid_contract, ["borderInventory"]), "today": today}
	not r.valid
	error_rules(r)["contract/border-inventory-must-be-array"]
}

test_empty_border_inventory if {
	r := enclave.validate with input as {"contract": object.union(valid_contract, {"borderInventory": []}), "today": today}
	not r.valid
	error_rules(r)["contract/border-inventory-required"]
}

test_border_entry_not_a_string if {
	c := object.union(valid_contract, {"borderInventory": ["checkout-web-tier", 7]})
	r := enclave.validate with input as {"contract": c, "today": today}
	not r.valid
	some f in r.findings
	f.rule == "contract/border-inventory-entry-must-be-string"
	f.path == "$.contract.borderInventory[1]"
}

test_missing_blast_radius if {
	r := enclave.validate with input as {"contract": object.remove(valid_contract, ["blastRadius"]), "today": today}
	not r.valid
	error_rules(r)["contract/blast-radius-must-be-object"]
}

test_blast_radius_missing_stated_limit if {
	c := object.union(object.remove(valid_contract, ["blastRadius"]), {"blastRadius": {"data": "Cart contents"}})
	r := enclave.validate with input as {"contract": c, "today": today}
	not r.valid
	some f in r.findings
	f.rule == "contract/blast-radius-field-required"
	f.path == "$.contract.blastRadius.statedLimit"
}

test_reviewed_on_bad_format if {
	r := enclave.validate with input as {"contract": object.union(valid_contract, {"reviewedOn": "2026-9-15"}), "today": today}
	not r.valid
	error_rules(r)["contract/reviewed-on-invalid"]
}

test_reviewed_on_impossible_date if {
	r := enclave.validate with input as {"contract": object.union(valid_contract, {"reviewedOn": "2026-02-30"}), "today": today}
	not r.valid
	error_rules(r)["contract/reviewed-on-invalid"]
}

test_reviewed_on_in_future if {
	r := enclave.validate with input as {"contract": object.union(valid_contract, {"reviewedOn": "2026-10-21"}), "today": today}
	not r.valid
	error_rules(r)["contract/reviewed-in-future"]
}

test_reviewed_on_stale if {
	r := enclave.validate with input as {"contract": object.union(valid_contract, {"reviewedOn": "2025-10-19"}), "today": today}
	not r.valid
	error_rules(r)["contract/reviewed-stale"]
}

test_reviewed_on_exactly_365_days_old_passes if {
	r := enclave.validate with input as {"contract": object.union(valid_contract, {"reviewedOn": "2025-10-20"}), "today": today}
	r.valid == true
}

test_extra_keys_are_tolerated if {
	r := enclave.validate with input as {"contract": object.union(valid_contract, {"notes": "Anything else you want to keep with the contract"}), "today": today}
	r.valid == true
}

# Enclave contract validator — The Software Field Guide, "Segmenting the Estate".
#
# An enclave contract records four answers plus a review date: who owns the
# enclave, which identity planes it trusts, which seams make up its border,
# and how far the blast radius reaches. This policy checks those answers
# against the house rules from the chapter and reports every violation with
# a path back into the document.
#
# Input (JSON): {"contract": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [{severity, rule, message, path}]}
#
# `valid` means: no error-severity findings. Warnings do not invalidate a
# contract; they mark answers that smell wrong. The clock is injected as
# `today` so the same contract validates identically in CI, offline, and
# in the browser playground.
package estate.enclave

import rego.v1

import data.estate.lib

# --- input ----------------------------------------------------------------

contract := object.get(input, "contract", null) if is_object(input)

contract_present if is_object(contract)

today := object.get(input, "today", null) if is_object(input)

# --- validation -----------------------------------------------------------

validate := result if {
	fs := sort([f | findings[f]])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
	}
}

# --- findings: input shape ------------------------------------------------

findings contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with 'contract' and 'today' fields",
		"path": "$",
	}
}

findings contains finding if {
	is_object(input)
	not lib.is_valid_date(today)
	finding := {
		"severity": "error",
		"rule": "input/today-invalid",
		"message": "today is missing or not a valid calendar date in YYYY-MM-DD format",
		"path": "$.today",
	}
}

findings contains finding if {
	is_object(input)
	not contract_present
	finding := {
		"severity": "error",
		"rule": "contract/missing",
		"message": "contract is missing or not an object",
		"path": "$.contract",
	}
}

# --- findings: required string fields --------------------------------------

required_string_fields := {
	"enclave": "enclave name",
	"owner": "owner",
	"reviewedOn": "review date",
}

findings contains finding if {
	contract_present
	some field, label in required_string_fields
	not lib.is_nonempty_string(object.get(contract, field, null))
	finding := {
		"severity": "error",
		"rule": "contract/required-field-missing",
		"message": sprintf("%s is required: it must be a non-empty string", [label]),
		"path": sprintf("$.contract.%s", [field]),
	}
}

# --- findings: trusted identity planes --------------------------------------

identity_planes := object.get(contract, "trustedIdentityPlanes", null) if contract_present

findings contains finding if {
	contract_present
	not is_array(identity_planes)
	finding := {
		"severity": "error",
		"rule": "contract/trusted-identity-planes-must-be-array",
		"message": "trustedIdentityPlanes must be an array of {plane, provider} objects",
		"path": "$.contract.trustedIdentityPlanes",
	}
}

findings contains finding if {
	contract_present
	is_array(identity_planes)
	count(identity_planes) == 0
	finding := {
		"severity": "error",
		"rule": "contract/trusted-identity-planes-required",
		"message": "trustedIdentityPlanes must list at least one plane: an enclave that trusts no identity serves no one",
		"path": "$.contract.trustedIdentityPlanes",
	}
}

findings contains finding if {
	contract_present
	is_array(identity_planes)
	some i, plane in identity_planes
	not is_object(plane)
	finding := {
		"severity": "error",
		"rule": "contract/identity-plane-must-be-object",
		"message": sprintf("trusted identity plane %d must be an object with 'plane' and 'provider'", [i]),
		"path": sprintf("$.contract.trustedIdentityPlanes[%d]", [i]),
	}
}

findings contains finding if {
	contract_present
	is_array(identity_planes)
	some i, plane in identity_planes
	is_object(plane)
	some field in {"plane", "provider"}
	not lib.is_nonempty_string(object.get(plane, field, null))
	finding := {
		"severity": "error",
		"rule": "contract/identity-plane-field-required",
		"message": sprintf("trusted identity plane %d: '%s' must be a non-empty string", [i, field]),
		"path": sprintf("$.contract.trustedIdentityPlanes[%d].%s", [i, field]),
	}
}

# --- findings: border inventory ---------------------------------------------

border_inventory := object.get(contract, "borderInventory", null) if contract_present

findings contains finding if {
	contract_present
	not is_array(border_inventory)
	finding := {
		"severity": "error",
		"rule": "contract/border-inventory-must-be-array",
		"message": "borderInventory must be an array of seam names",
		"path": "$.contract.borderInventory",
	}
}

findings contains finding if {
	contract_present
	is_array(border_inventory)
	count(border_inventory) == 0
	finding := {
		"severity": "error",
		"rule": "contract/border-inventory-required",
		"message": "borderInventory must list at least one seam: every enclave has a border, and this is where you declare it",
		"path": "$.contract.borderInventory",
	}
}

findings contains finding if {
	contract_present
	is_array(border_inventory)
	some i, seam in border_inventory
	not lib.is_nonempty_string(seam)
	finding := {
		"severity": "error",
		"rule": "contract/border-inventory-entry-must-be-string",
		"message": sprintf("border inventory entry %d must be a non-empty string (a seam name)", [i]),
		"path": sprintf("$.contract.borderInventory[%d]", [i]),
	}
}

# --- findings: blast radius ----------------------------------------------------

blast_radius := object.get(contract, "blastRadius", null) if contract_present

findings contains finding if {
	contract_present
	not is_object(blast_radius)
	finding := {
		"severity": "error",
		"rule": "contract/blast-radius-must-be-object",
		"message": "blastRadius must be an object with 'data' and 'statedLimit'",
		"path": "$.contract.blastRadius",
	}
}

findings contains finding if {
	contract_present
	is_object(blast_radius)
	some field in {"data", "statedLimit"}
	not lib.is_nonempty_string(object.get(blast_radius, field, null))
	finding := {
		"severity": "error",
		"rule": "contract/blast-radius-field-required",
		"message": sprintf("blastRadius.%s is required and must be a non-empty string", [field]),
		"path": sprintf("$.contract.blastRadius.%s", [field]),
	}
}

# --- findings: review date -------------------------------------------------------

reviewed_on := object.get(contract, "reviewedOn", null) if contract_present

findings contains finding if {
	contract_present
	is_string(reviewed_on)
	not lib.is_valid_date(reviewed_on)
	finding := {
		"severity": "error",
		"rule": "contract/reviewed-on-invalid",
		"message": "reviewedOn must be a valid calendar date in YYYY-MM-DD format",
		"path": "$.contract.reviewedOn",
	}
}

findings contains finding if {
	contract_present
	lib.is_valid_date(today)
	lib.is_valid_date(reviewed_on)
	lib.date_to_days(reviewed_on) > lib.date_to_days(today)
	finding := {
		"severity": "error",
		"rule": "contract/reviewed-in-future",
		"message": "reviewedOn lies in the future: a contract records a review that happened, not one you intend",
		"path": "$.contract.reviewedOn",
	}
}

findings contains finding if {
	contract_present
	lib.is_valid_date(today)
	lib.is_valid_date(reviewed_on)
	lib.date_to_days(today) - lib.date_to_days(reviewed_on) > 365
	finding := {
		"severity": "error",
		"rule": "contract/reviewed-stale",
		"message": "reviewedOn is more than 365 days before today: this enclave contract is stale",
		"path": "$.contract.reviewedOn",
	}
}

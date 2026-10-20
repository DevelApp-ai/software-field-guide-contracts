# Estate bundle validator — The Software Field Guide, "Segmenting the Estate".
#
# Validates a set of enclave and seam contracts together. The per-contract
# policies (estate.enclave, estate.seam) judge each contract on its own;
# this policy judges the estate as a whole: names are unique, every seam
# belongs to an enclave, and every seam an enclave declares on its border
# actually has a seam contract behind it.
#
# Input (JSON): {"enclaves": [...], "seams": [...]}
# Result:       {"valid": bool, "findings": [{severity, rule, message, path}]}
package estate.cross

import rego.v1

import data.estate.lib

# --- input ----------------------------------------------------------------

enclaves := object.get(input, "enclaves", null) if is_object(input)

seams := object.get(input, "seams", null) if is_object(input)

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
		"message": "input must be an object with 'enclaves' and 'seams' arrays",
		"path": "$",
	}
}

findings contains finding if {
	is_object(input)
	not is_array(enclaves)
	finding := {
		"severity": "error",
		"rule": "bundle/enclaves-must-be-array",
		"message": "enclaves must be an array of enclave contracts",
		"path": "$.enclaves",
	}
}

findings contains finding if {
	is_object(input)
	not is_array(seams)
	finding := {
		"severity": "error",
		"rule": "bundle/seams-must-be-array",
		"message": "seams must be an array of seam contracts",
		"path": "$.seams",
	}
}

# --- helpers --------------------------------------------------------------

# The declared name of the contract at `items[i]`, or undefined when the
# entry has no usable name. `key` is "enclave" or "seam".
name_at(items, key, i) := name if {
	e := items[i]
	is_object(e)
	name := object.get(e, key, null)
	is_string(name)
	name != ""
}

# True when some later entry repeats `name` at or after position `i`.
duplicate_name(items, key, name, i) if {
	some j, other in items
	j > i
	name_at(items, key, j) == name
}

# True when some earlier entry already used `name` before position `i`.
earlier_name(items, key, name, i) if {
	some j, other in items
	j < i
	name_at(items, key, j) == name
}

default enclave_names := {}

enclave_names := names if {
	is_array(enclaves)
	names := {name | some i, e in enclaves; name := name_at(enclaves, "enclave", i)}
}

default seam_names := {}

seam_names := names if {
	is_array(seams)
	names := {name | some i, s in seams; name := name_at(seams, "seam", i)}
}

default border_seams := {}

border_seams := names if {
	is_array(enclaves)
	names := {seam |
		some e in enclaves
		is_object(e)
		inventory := object.get(e, "borderInventory", [])
		is_array(inventory)
		some seam in inventory
		lib.is_nonempty_string(seam)
	}
}

# --- findings: duplicate names --------------------------------------------
#
# One finding per duplicated name, reported at its first occurrence.

findings contains finding if {
	is_array(enclaves)
	some i, e in enclaves
	name := name_at(enclaves, "enclave", i)
	duplicate_name(enclaves, "enclave", name, i)
	not earlier_name(enclaves, "enclave", name, i)
	finding := {
		"severity": "error",
		"rule": "bundle/duplicate-enclave-name",
		"message": sprintf("enclave name '%s' appears more than once", [name]),
		"path": sprintf("$.enclaves[%d]", [i]),
	}
}

findings contains finding if {
	is_array(seams)
	some i, s in seams
	name := name_at(seams, "seam", i)
	duplicate_name(seams, "seam", name, i)
	not earlier_name(seams, "seam", name, i)
	finding := {
		"severity": "error",
		"rule": "bundle/duplicate-seam-name",
		"message": sprintf("seam name '%s' appears more than once", [name]),
		"path": sprintf("$.seams[%d]", [i]),
	}
}

# --- findings: seams without an owning enclave ------------------------------

findings contains finding if {
	is_array(enclaves)
	is_array(seams)
	some i, s in seams
	is_object(s)
	owner := object.get(s, "enclave", null)
	lib.is_nonempty_string(owner)
	not owner in enclave_names
	finding := {
		"severity": "error",
		"rule": "bundle/seam-enclave-unknown",
		"message": sprintf("seam '%s' references enclave '%s', but no enclave contract defines it", [seam_label(s), owner]),
		"path": sprintf("$.seams[%d].enclave", [i]),
	}
}

seam_label(s) := name if {
	name := object.get(s, "seam", null)
	lib.is_nonempty_string(name)
}

seam_label(s) := "(unnamed seam)" if {
	not lib.is_nonempty_string(object.get(s, "seam", null))
}

# --- findings: border inventory without seam contracts ------------------------

findings contains finding if {
	is_array(enclaves)
	is_array(seams)
	some i, e in enclaves
	is_object(e)
	inventory := object.get(e, "borderInventory", [])
	is_array(inventory)
	some k, seam in inventory
	lib.is_nonempty_string(seam)
	not seam in seam_names
	finding := {
		"severity": "error",
		"rule": "bundle/border-seam-without-contract",
		"message": sprintf("border inventory lists seam '%s', but no seam contract exists for it", [seam]),
		"path": sprintf("$.enclaves[%d].borderInventory[%d]", [i, k]),
	}
}

# --- findings: seam contracts no enclave claims -------------------------------

findings contains finding if {
	is_array(enclaves)
	is_array(seams)
	some i, s in seams
	name := name_at(seams, "seam", i)
	not name in border_seams
	finding := {
		"severity": "warning",
		"rule": "bundle/seam-not-in-inventory",
		"message": sprintf("seam contract '%s' is not listed in any enclave's borderInventory", [name]),
		"path": sprintf("$.seams[%d]", [i]),
	}
}

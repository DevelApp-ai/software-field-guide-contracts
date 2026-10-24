# Action registry validator — The Software Field Guide, issue #70.
#
# Judges the action registry on its own: the micro-action contract
# anatomy the bounded-agent-execution chapter defines. Every action is
# named (one action, one callable name — the unit of audit and
# revocation), typed (one of the four execution families), and
# parameter-checked (a declared schema with validation rules, because
# the engine rejects anything undeclared before execution). Every
# action carries its execution envelope — a bounded timeout and memory
# that physically cannot exceed the platform ceilings — and scripted
# actions must demand sidecar isolation. Every consequential security
# level must demand explicit confirmation: auto-confirm past the gate's
# classification is the failure the issue names. External server
# actions must reference a registered, approved server — the boundary
# grows only by explicit, reviewed registration, never by silent
# discovery.
#
# Input (JSON): {"registry": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [{severity, rule, message, path}]}
package actions

import rego.v1

import data.actions.lib

# --- entrypoint -------------------------------------------------------------

validate := result if {
	fs := sort([f | some f in validate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
	}
}

validate_findings := (((((((((((((f_input_invalid | f_today_invalid) | f_registry_missing) | f_stamps) | f_ceilings) | f_servers_array) | f_server_content) | f_actions_array) | f_action_identity) | f_action_type) | f_action_parameters) | f_action_outputs) | f_action_envelope) | f_action_classification) | f_action_server

# --- findings: input shape ----------------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the action registry as input.registry",
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

# --- findings: the document is missing -------------------------------------------

f_registry_missing contains finding if {
	not is_object(registry_doc)
	finding := {
		"severity": "error",
		"rule": "registry/missing",
		"message": "the action registry is required: pass it as input.registry",
		"path": "$.registry",
	}
}

# --- findings: version and review stamps -------------------------------------------

# The registry is versioned like code: an action vocabulary that can
# silently change is folklore, not a contract.
f_stamps contains finding if {
	is_object(registry_doc)
	not is_positive_integer(object.get(registry_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "registry/version-required",
		"message": "the action registry must carry a version (a positive integer): the vocabulary is versioned like code",
		"path": "$.registry.version",
	}
}

f_stamps contains finding if {
	is_object(registry_doc)
	not lib.is_valid_date(object.get(registry_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "registry/reviewed-on-invalid",
		"message": "the action registry must carry reviewedOn as a real YYYY-MM-DD date",
		"path": "$.registry.reviewedOn",
	}
}

f_stamps contains finding if {
	is_object(registry_doc)
	lib.is_valid_date(object.get(registry_doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(registry_doc, "reviewedOn", null)) > lib.date_to_days(object.get(input, "today", null))
	finding := {
		"severity": "error",
		"rule": "registry/reviewed-in-future",
		"message": "the action registry carries a reviewedOn date in the future",
		"path": "$.registry.reviewedOn",
	}
}

f_stamps contains finding if {
	is_object(registry_doc)
	lib.is_valid_date(object.get(registry_doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(input, "today", null)) - lib.date_to_days(object.get(registry_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "registry/reviewed-stale",
		"message": "the action registry was reviewed more than 365 days before today: this document is stale",
		"path": "$.registry.reviewedOn",
	}
}

is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# --- findings: the platform ceilings ------------------------------------------------

# The ceilings are what makes an envelope breach decidable: a run can
# only be judged against a limit the platform declared.
f_ceilings contains finding if {
	is_object(registry_doc)
	not is_object(object.get(registry_doc, "platformCeilings", null))
	finding := {
		"severity": "error",
		"rule": "registry/ceilings-required",
		"message": "the registry must declare platformCeilings with maxTimeoutSeconds and maxMemoryMB: an envelope can only be judged against a declared ceiling",
		"path": "$.registry.platformCeilings",
	}
}

f_ceilings contains finding if {
	is_object(registry_doc)
	is_object(platform_ceilings)
	not is_positive_number(object.get(platform_ceilings, "maxTimeoutSeconds", null))
	finding := {
		"severity": "error",
		"rule": "registry/ceiling-timeout-invalid",
		"message": "platformCeilings.maxTimeoutSeconds must be a positive number of seconds",
		"path": "$.registry.platformCeilings.maxTimeoutSeconds",
	}
}

f_ceilings contains finding if {
	is_object(registry_doc)
	is_object(platform_ceilings)
	not is_positive_number(object.get(platform_ceilings, "maxMemoryMB", null))
	finding := {
		"severity": "error",
		"rule": "registry/ceiling-memory-invalid",
		"message": "platformCeilings.maxMemoryMB must be a positive number of megabytes",
		"path": "$.registry.platformCeilings.maxMemoryMB",
	}
}

# --- findings: registered servers ------------------------------------------------------

f_servers_array contains finding if {
	is_object(registry_doc)
	not is_array(object.get(registry_doc, "servers", null))
	finding := {
		"severity": "error",
		"rule": "servers/must-be-array",
		"message": "servers must be an array of {name, approved} entries",
		"path": "$.registry.servers",
	}
}

f_server_content contains finding if {
	some i, s in as_array(registry_doc, "servers")
	not is_object(s)
	finding := {
		"severity": "error",
		"rule": "servers/entry-must-be-object",
		"message": sprintf("server entry %d must be an object with name and approved", [i]),
		"path": sprintf("$.registry.servers[%d]", [i]),
	}
}

f_server_content contains finding if {
	some i, s in servers
	not lib.is_nonempty_string(object.get(s, "name", null))
	finding := {
		"severity": "error",
		"rule": "server/name-required",
		"message": sprintf("server entry %d must carry a non-empty name", [i]),
		"path": sprintf("$.registry.servers[%d].name", [i]),
	}
}

f_server_content contains finding if {
	some i, s in servers
	not is_boolean(object.get(s, "approved", null))
	finding := {
		"severity": "error",
		"rule": "server/approved-required",
		"message": sprintf("server '%s' must state approved as a boolean: trust is granted at registration time and reviewed, never implied", [object.get(s, "name", "unnamed")]),
		"path": sprintf("$.registry.servers[%d].approved", [i]),
	}
}

f_server_content contains finding if {
	names := [object.get(s, "name", null) |
		some s in servers
		lib.is_nonempty_string(object.get(s, "name", null))
	]
	some name in names
	count([n | some n in names; n == name]) > 1
	finding := {
		"severity": "error",
		"rule": "server/name-duplicate",
		"message": sprintf("server '%s' is registered more than once", [name]),
		"path": "$.registry.servers",
	}
}

# --- findings: the actions array -------------------------------------------------------

f_actions_array contains finding if {
	is_object(registry_doc)
	not is_array(object.get(registry_doc, "actions", null))
	finding := {
		"severity": "error",
		"rule": "actions/must-be-array",
		"message": "actions must be an array of micro-action contracts",
		"path": "$.registry.actions",
	}
}

f_actions_array contains finding if {
	is_object(registry_doc)
	is_array(object.get(registry_doc, "actions", null))
	count(actions_list) == 0
	finding := {
		"severity": "error",
		"rule": "actions/required",
		"message": "the registry must declare at least one action: a vocabulary with no actions is a chat-only assistant",
		"path": "$.registry.actions",
	}
}

f_actions_array contains finding if {
	some i, a in as_array(registry_doc, "actions")
	not is_object(a)
	finding := {
		"severity": "error",
		"rule": "actions/entry-must-be-object",
		"message": sprintf("action entry %d must be an object with the micro-action contract anatomy", [i]),
		"path": sprintf("$.registry.actions[%d]", [i]),
	}
}

# --- findings: identity — one action, one callable name ---------------------------------

f_action_identity contains finding if {
	some i, a in actions_list
	not lib.is_nonempty_string(object.get(a, "id", null))
	finding := {
		"severity": "error",
		"rule": "action/id-required",
		"message": sprintf("action entry %d must carry a non-empty id: one action, one callable name — the unit of audit and revocation", [i]),
		"path": sprintf("$.registry.actions[%d].id", [i]),
	}
}

f_action_identity contains finding if {
	ids := [object.get(a, "id", null) |
		some a in actions_list
		lib.is_nonempty_string(object.get(a, "id", null))
	]
	some id in ids
	count([x | some x in ids; x == id]) > 1
	finding := {
		"severity": "error",
		"rule": "action/id-duplicate",
		"message": sprintf("action '%s' is declared more than once: revoking a name must revoke one action", [id]),
		"path": "$.registry.actions",
	}
}

f_action_identity contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	not lib.is_nonempty_string(object.get(a, "name", null))
	finding := {
		"severity": "error",
		"rule": "action/name-required",
		"message": sprintf("action '%s' must carry a human-readable name", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].name", [i]),
	}
}

f_action_identity contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	not lib.is_nonempty_string(object.get(a, "description", null))
	finding := {
		"severity": "error",
		"rule": "action/description-required",
		"message": sprintf("action '%s' must carry a description: a capability nobody can describe is a capability nobody can review", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].description", [i]),
	}
}

# --- findings: type — the execution family ----------------------------------------------

f_action_type contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	not lib.is_nonempty_string(action_type(a))
	finding := {
		"severity": "error",
		"rule": "action/type-required",
		"message": sprintf("action '%s' must declare its type: the execution family decides what the engine may run", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].type", [i]),
	}
}

f_action_type contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	lib.is_nonempty_string(action_type(a))
	not action_type(a) in action_types_known
	finding := {
		"severity": "error",
		"rule": "action/type-unknown",
		"message": sprintf("action '%s' declares type '%s', which is not one of the four execution families (%s)", [
			object.get(a, "id", null),
			action_type(a),
			concat(", ", sort(action_types_known)),
		]),
		"path": sprintf("$.registry.actions[%d].type", [i]),
	}
}

# --- findings: parameters — the typed, checked schema ------------------------------------

f_action_parameters contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	not is_array(object.get(a, "parameters", null))
	finding := {
		"severity": "error",
		"rule": "action/parameters-must-be-array",
		"message": sprintf("action '%s' must declare parameters as an array of typed parameters (an action with no parameters declares an empty array)", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].parameters", [i]),
	}
}

f_action_parameters contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	some j, p in action_parameters(a)
	not is_object(p)
	finding := {
		"severity": "error",
		"rule": "action/parameter-must-be-object",
		"message": sprintf("parameter %d of action '%s' must be an object with name, type, and validation", [j, object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].parameters[%d]", [i, j]),
	}
}

f_action_parameters contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	some j, p in action_parameters(a)
	is_object(p)
	not lib.is_nonempty_string(object.get(p, "name", null))
	finding := {
		"severity": "error",
		"rule": "action/parameter-name-required",
		"message": sprintf("parameter %d of action '%s' must carry a non-empty name: the scope of a grant constrains arguments by this name", [j, object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].parameters[%d].name", [i, j]),
	}
}

# The issue's own headline: an action that skips its parameter checks
# ships if a reviewer misses it. A parameter without a type is a
# parameter the engine cannot check.
f_action_parameters contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	some j, p in action_parameters(a)
	is_object(p)
	lib.is_nonempty_string(object.get(p, "name", null))
	not lib.is_nonempty_string(object.get(p, "type", null))
	finding := {
		"severity": "error",
		"rule": "action/parameter-untyped",
		"message": sprintf("parameter '%s' of action '%s' lacks a type: the engine validates arguments against the declaration — an untyped parameter is a parameter nobody checks", [
			object.get(p, "name", null),
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].parameters[%d].type", [i, j]),
	}
}

f_action_parameters contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	some j, p in action_parameters(a)
	is_object(p)
	lib.is_nonempty_string(object.get(p, "type", null))
	not object.get(p, "type", null) in parameter_types_known
	finding := {
		"severity": "error",
		"rule": "action/parameter-type-unknown",
		"message": sprintf("parameter '%s' of action '%s' declares type '%s', which is not one of the declared parameter types (%s)", [
			object.get(p, "name", null),
			object.get(a, "id", null),
			object.get(p, "type", null),
			concat(", ", sort(parameter_types_known)),
		]),
		"path": sprintf("$.registry.actions[%d].parameters[%d].type", [i, j]),
	}
}

# A typed parameter must also carry its validation: the declared
# schema's checks are what the engine enforces before anything runs.
f_action_parameters contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	some j, p in action_parameters(a)
	is_object(p)
	lib.is_nonempty_string(object.get(p, "name", null))
	not is_object(object.get(p, "validation", null))
	finding := {
		"severity": "error",
		"rule": "action/parameter-validation-required",
		"message": sprintf("parameter '%s' of action '%s' must carry a validation object: the declared checks are what the engine enforces — a schema without checks is documentation, not validation", [
			object.get(p, "name", null),
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].parameters[%d].validation", [i, j]),
	}
}

# An enum declared with no values is a check that cannot check.
f_action_parameters contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	some j, p in action_parameters(a)
	is_object(p)
	lib.is_nonempty_string(object.get(p, "name", null))
	is_object(object.get(p, "validation", null))
	"enumValues" in object.keys(object.get(p, "validation", {}))
	not is_array(object.get(object.get(p, "validation", {}), "enumValues", null))
	finding := {
		"severity": "error",
		"rule": "action/parameter-enum-values-required",
		"message": sprintf("parameter '%s' of action '%s' declares enumValues, which must be a non-empty array of allowed values", [
			object.get(p, "name", null),
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].parameters[%d].validation.enumValues", [i, j]),
	}
}

f_action_parameters contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	some j, p in action_parameters(a)
	is_object(p)
	lib.is_nonempty_string(object.get(p, "name", null))
	is_object(object.get(p, "validation", null))
	"enumValues" in object.keys(object.get(p, "validation", {}))
	is_array(object.get(object.get(p, "validation", {}), "enumValues", null))
	count(object.get(object.get(p, "validation", {}), "enumValues", null)) == 0
	finding := {
		"severity": "error",
		"rule": "action/parameter-enum-values-required",
		"message": sprintf("parameter '%s' of action '%s' declares enumValues, which must be a non-empty array of allowed values", [
			object.get(p, "name", null),
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].parameters[%d].validation.enumValues", [i, j]),
	}
}

f_action_parameters contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	names := [object.get(p, "name", null) |
		some p in action_parameters(a)
		is_object(p)
		lib.is_nonempty_string(object.get(p, "name", null))
	]
	some name in names
	count([n | some n in names; n == name]) > 1
	finding := {
		"severity": "error",
		"rule": "action/parameter-name-duplicate",
		"message": sprintf("parameter '%s' is declared more than once on action '%s': an argument is one value, a duplicate name is two claims on it", [
			name,
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].parameters", [i]),
	}
}

# --- findings: outputs — the declared result shape -----------------------------------------

f_action_outputs contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	not is_object(action_outputs(a))
	finding := {
		"severity": "error",
		"rule": "action/outputs-required",
		"message": sprintf("action '%s' must declare its outputs: consumers build against the declared shape — an undeclared result is a rumor", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].outputs", [i]),
	}
}

f_action_outputs contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	is_object(action_outputs(a))
	count(action_outputs(a)) == 0
	finding := {
		"severity": "error",
		"rule": "action/outputs-required",
		"message": sprintf("action '%s' must declare at least one output: consumers build against the declared shape", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].outputs", [i]),
	}
}

# --- findings: the execution envelope ----------------------------------------------------------

f_action_envelope contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	not is_object(action_envelope(a))
	finding := {
		"severity": "error",
		"rule": "envelope/invalid",
		"message": sprintf("action '%s' must carry an execution envelope {timeoutSeconds, maxMemoryMB, useIsolation}: the envelope is where safety stops being an aspiration", [
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].envelope", [i]),
	}
}

f_action_envelope contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	is_object(action_envelope(a))
	not is_positive_number(object.get(action_envelope(a), "timeoutSeconds", null))
	finding := {
		"severity": "error",
		"rule": "envelope/timeout-required",
		"message": sprintf("action '%s' must declare envelope.timeoutSeconds as a positive number: a hung tool must fail closed, not hold the loop open", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].envelope.timeoutSeconds", [i]),
	}
}

f_action_envelope contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	is_object(action_envelope(a))
	not is_positive_number(object.get(action_envelope(a), "maxMemoryMB", null))
	finding := {
		"severity": "error",
		"rule": "envelope/memory-required",
		"message": sprintf("action '%s' must declare envelope.maxMemoryMB as a positive number: a run physically cannot outgrow its declared memory", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].envelope.maxMemoryMB", [i]),
	}
}

# The platform ceiling is the ceiling: a declared envelope may be
# tighter, never past what the platform promised to enforce.
f_action_envelope contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	is_object(action_envelope(a))
	is_positive_number(object.get(action_envelope(a), "timeoutSeconds", null))
	ceilings_valid
	is_positive_number(object.get(platform_ceilings, "maxTimeoutSeconds", null))
	object.get(action_envelope(a), "timeoutSeconds", null) > object.get(platform_ceilings, "maxTimeoutSeconds", null)
	finding := {
		"severity": "error",
		"rule": "envelope/exceeds-ceiling",
		"message": sprintf("action '%s' declares a timeout of %d seconds, past the platform ceiling of %d: the ceiling is what the platform enforces — a contract cannot promise more", [
			object.get(a, "id", null),
			object.get(action_envelope(a), "timeoutSeconds", null),
			object.get(platform_ceilings, "maxTimeoutSeconds", null),
		]),
		"path": sprintf("$.registry.actions[%d].envelope.timeoutSeconds", [i]),
	}
}

f_action_envelope contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	is_object(action_envelope(a))
	is_positive_number(object.get(action_envelope(a), "maxMemoryMB", null))
	ceilings_valid
	is_positive_number(object.get(platform_ceilings, "maxMemoryMB", null))
	object.get(action_envelope(a), "maxMemoryMB", null) > object.get(platform_ceilings, "maxMemoryMB", null)
	finding := {
		"severity": "error",
		"rule": "envelope/exceeds-ceiling",
		"message": sprintf("action '%s' declares a memory limit of %d MB, past the platform ceiling of %d: the ceiling is what the platform enforces — a contract cannot promise more", [
			object.get(a, "id", null),
			object.get(action_envelope(a), "maxMemoryMB", null),
			object.get(platform_ceilings, "maxMemoryMB", null),
		]),
		"path": sprintf("$.registry.actions[%d].envelope.maxMemoryMB", [i]),
	}
}

# Scripted actions run in sidecar containers with limits enforced from
# the contract, not from convention: a Python or C# action without
# isolation is free-form execution wearing a typed hat.
f_action_envelope contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	action_type(a) in scripted_types
	is_object(action_envelope(a))
	object.get(action_envelope(a), "useIsolation", null) != true
	finding := {
		"severity": "error",
		"rule": "envelope/isolation-required",
		"message": sprintf("action '%s' is a scripted %s action and must set envelope.useIsolation to true: scripted actions run in sidecar isolation — limits enforced from the contract, not from convention", [
			object.get(a, "id", null),
			action_type(a),
		]),
		"path": sprintf("$.registry.actions[%d].envelope.useIsolation", [i]),
	}
}

# --- findings: security level, confirmation, effect ----------------------------------------------

f_action_classification contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	not lib.is_nonempty_string(action_security_level(a))
	finding := {
		"severity": "error",
		"rule": "action/security-level-required",
		"message": sprintf("action '%s' must declare its security level: progressive restrictions hang off it", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].securityLevel", [i]),
	}
}

f_action_classification contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	lib.is_nonempty_string(action_security_level(a))
	not action_security_level(a) in security_levels_known
	finding := {
		"severity": "error",
		"rule": "action/security-level-unknown",
		"message": sprintf("action '%s' declares security level '%s', which is not one of the declared levels (%s)", [
			object.get(a, "id", null),
			action_security_level(a),
			concat(", ", sort(security_levels_known)),
		]),
		"path": sprintf("$.registry.actions[%d].securityLevel", [i]),
	}
}

f_action_classification contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	not lib.is_nonempty_string(action_confirmation(a))
	finding := {
		"severity": "error",
		"rule": "action/confirmation-required",
		"message": sprintf("action '%s' must declare its confirmation mode (confirm or auto-confirm): the confirmation surface is what does the work a shell prompt otherwise would", [
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].confirmation", [i]),
	}
}

f_action_classification contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	lib.is_nonempty_string(action_confirmation(a))
	not action_confirmation(a) in confirmations_known
	finding := {
		"severity": "error",
		"rule": "action/confirmation-unknown",
		"message": sprintf("action '%s' declares confirmation '%s', which is neither confirm nor auto-confirm", [
			object.get(a, "id", null),
			action_confirmation(a),
		]),
		"path": sprintf("$.registry.actions[%d].confirmation", [i]),
	}
}

# The gate's classification, enforced: explicit confirmation for
# consequential actions, auto-confirm for low-risk ones. An action that
# auto-confirms at High or Critical bypasses the classification the
# confirmation gate exists to make.
f_action_classification contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	action_security_level(a) in confirm_levels
	action_confirmation(a) == "auto-confirm"
	finding := {
		"severity": "error",
		"rule": "action/confirm-required-at-level",
		"message": sprintf("action '%s' is a %s action and must require explicit confirmation: auto-confirm past the gate's classification is the failure mode", [
			object.get(a, "id", null),
			action_security_level(a),
		]),
		"path": sprintf("$.registry.actions[%d].confirmation", [i]),
	}
}

f_action_classification contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	not lib.is_nonempty_string(action_effect(a))
	finding := {
		"severity": "error",
		"rule": "action/effect-required",
		"message": sprintf("action '%s' must declare its effect (read or write): the staged autonomy ladder is enforced against it", [
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].effect", [i]),
	}
}

f_action_classification contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	lib.is_nonempty_string(action_effect(a))
	not action_effect(a) in effects_known
	finding := {
		"severity": "error",
		"rule": "action/effect-unknown",
		"message": sprintf("action '%s' declares effect '%s', which is neither read nor write", [
			object.get(a, "id", null),
			action_effect(a),
		]),
		"path": sprintf("$.registry.actions[%d].effect", [i]),
	}
}

# --- findings: external server references -----------------------------------------------------------

f_action_server contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	action_type(a) == "ExternalServer"
	not is_object(action_server(a))
	finding := {
		"severity": "error",
		"rule": "action/server-required",
		"message": sprintf("external action '%s' must reference a registered server {name, operation, mappings}: the boundary grows only by registration, never by silent discovery", [
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].server", [i]),
	}
}

f_action_server contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	action_type(a) == "ExternalServer"
	is_object(action_server(a))
	not lib.is_nonempty_string(object.get(action_server(a), "name", null))
	finding := {
		"severity": "error",
		"rule": "action/server-name-required",
		"message": sprintf("external action '%s' must name the registered server it calls", [object.get(a, "id", null)]),
		"path": sprintf("$.registry.actions[%d].server.name", [i]),
	}
}

f_action_server contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	action_type(a) == "ExternalServer"
	is_object(action_server(a))
	lib.is_nonempty_string(object.get(action_server(a), "name", null))
	not object.get(action_server(a), "name", null) in server_names
	finding := {
		"severity": "error",
		"rule": "action/server-unknown",
		"message": sprintf("external action '%s' references server '%s', which the registry has not registered: an unregistered call is free-form execution with extra steps", [
			object.get(a, "id", null),
			object.get(action_server(a), "name", null),
		]),
		"path": sprintf("$.registry.actions[%d].server.name", [i]),
	}
}

# Registration is where the trust decision lives: a call against an
# unapproved server is a call nobody reviewed.
f_action_server contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	action_type(a) == "ExternalServer"
	is_object(action_server(a))
	lib.is_nonempty_string(object.get(action_server(a), "name", null))
	object.get(action_server(a), "name", null) in server_names
	not server_approved(object.get(action_server(a), "name", null))
	finding := {
		"severity": "error",
		"rule": "action/server-unapproved",
		"message": sprintf("external action '%s' calls server '%s', which is registered but not approved: trust is granted at registration time and reviewed — never assumed", [
			object.get(a, "id", null),
			object.get(action_server(a), "name", null),
		]),
		"path": sprintf("$.registry.actions[%d].server.name", [i]),
	}
}

f_action_server contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	action_type(a) == "ExternalServer"
	is_object(action_server(a))
	not lib.is_nonempty_string(object.get(action_server(a), "operation", null))
	finding := {
		"severity": "error",
		"rule": "action/server-operation-required",
		"message": sprintf("external action '%s' must name the operation it calls on the registered server: a call without an operation is a door without a handle", [
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].server.operation", [i]),
	}
}

f_action_server contains finding if {
	some i, a in actions_list
	action_row_well_formed(a)
	action_type(a) == "ExternalServer"
	is_object(action_server(a))
	not is_object(object.get(action_server(a), "mappings", null))
	finding := {
		"severity": "error",
		"rule": "action/server-mappings-required",
		"message": sprintf("external action '%s' must declare its parameter mappings: an external call is as typed, validated, and auditable as a local one", [
			object.get(a, "id", null),
		]),
		"path": sprintf("$.registry.actions[%d].server.mappings", [i]),
	}
}

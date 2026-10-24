# The shared model for the action scope validator — The Software Field
# Guide, issue #70.
#
# Two documents enter: the action registry (the micro-action contract
# anatomy — named, typed, parameter-checked actions with enforced
# resource envelopes and registered external servers) and the agent
# permission manifest (the kill-switch chapter's default-deny scoping:
# per-agent grants, argument-level scopes, and the staged autonomy
# ladder). The registry is what the engine may execute; the manifest is
# who may ask for it. Every accessor here guards its input before
# touching object fields — a malformed document must produce findings,
# never a WASM trap.
package actions

import rego.v1

import data.actions.lib

# --- the input documents ------------------------------------------------------

registry_doc := v if {
	is_object(input)
	v := object.get(input, "registry", null)
}

registry_doc := null if not is_object(input)

manifest_doc := v if {
	is_object(input)
	v := object.get(input, "manifest", null)
}

manifest_doc := null if not is_object(input)

# --- arrays, defensively ------------------------------------------------------

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

# --- the vocabulary, as declared facts ----------------------------------------

# The registry's closed vocabularies: an action type, a parameter type,
# a security level, a confirmation mode, an effect, and an agent stage
# are defined facts, not judgment calls made at runtime.
action_types_known := {"AgenticPrompt", "PythonScript", "CSharpScript", "ExternalServer"}

parameter_types_known := {"string", "number", "boolean"}

security_levels_known := {"Low", "Standard", "High", "Critical"}

confirmations_known := {"confirm", "auto-confirm"}

effects_known := {"read", "write"}

stages_known := {"autonomous", "propose-only", "read-only", "quarantined"}

# The scripted families: code that runs in the platform's isolation,
# so the contract must demand a sidecar.
scripted_types := {"PythonScript", "CSharpScript"}

# The security levels that demand an explicit human confirmation: the
# gate's classification — low-risk requests may auto-confirm,
# consequential ones may not.
confirm_levels := {"High", "Critical"}

# --- the registry: platform ceilings -----------------------------------------

platform_ceilings := object.get(registry_doc, "platformCeilings", null) if is_object(registry_doc)

platform_ceilings := null if not is_object(registry_doc)

is_positive_number(v) if {
	is_number(v)
	v > 0
}

# The ceilings are only usable for the exceeds-ceiling judgment when
# both limits are declared as positive numbers.
ceilings_valid if {
	is_object(platform_ceilings)
	is_positive_number(object.get(platform_ceilings, "maxTimeoutSeconds", null))
	is_positive_number(object.get(platform_ceilings, "maxMemoryMB", null))
}

# --- the registry: servers -----------------------------------------------------

servers := [s | some s in as_array(registry_doc, "servers"); is_object(s)]

server_names := {object.get(s, "name", null) |
	some s in servers
	lib.is_nonempty_string(object.get(s, "name", null))
}

server_index(name) := i if {
	matches := [i |
		some i, s in servers
		object.get(s, "name", null) == name
	]
	count(matches) > 0
	i := matches[0]
}

approved_servers := {object.get(s, "name", null) |
	some s in servers
	object.get(s, "approved", null) == true
	lib.is_nonempty_string(object.get(s, "name", null))
}

server_approved(name) if name in approved_servers

# --- the registry: the actions themselves ---------------------------------------

actions_list := [a | some a in as_array(registry_doc, "actions"); is_object(a)]

action_ids := {object.get(a, "id", null) |
	some a in actions_list
	lib.is_nonempty_string(object.get(a, "id", null))
}

action_index(id) := i if {
	matches := [i |
		some i, a in actions_list
		object.get(a, "id", null) == id
	]
	count(matches) > 0
	i := matches[0]
}

# The declared action behind an id — duplicate ids are the validator's
# finding, never an ambiguity for lookups.
action(id) := a if {
	matches := [a |
		some a in actions_list
		object.get(a, "id", null) == id
	]
	count(matches) > 0
	a := matches[0]
}

# --- per-action accessors ------------------------------------------------------

action_type(a) := object.get(a, "type", null)

action_security_level(a) := object.get(a, "securityLevel", null)

action_confirmation(a) := object.get(a, "confirmation", null)

action_effect(a) := object.get(a, "effect", null)

action_outputs(a) := object.get(a, "outputs", null)

action_envelope(a) := object.get(a, "envelope", null)

action_server(a) := object.get(a, "server", null)

action_parameters(a) := as_array(a, "parameters")

# The parameter names one action declares — the vocabulary an
# argument scope may constrain. Duplicate names are the validator's
# finding, never an ambiguity for scope checks.
action_parameter_names(a) := {object.get(p, "name", null) |
	some p in action_parameters(a)
	lib.is_nonempty_string(object.get(p, "name", null))
}

action_row_well_formed(a) if {
	is_object(a)
	lib.is_nonempty_string(object.get(a, "id", null))
}

# --- the manifest: agents and grants ---------------------------------------------

agents := [g | some g in as_array(manifest_doc, "agents"); is_object(g)]

agent_name(g) := object.get(g, "agent", null)

agent_stage(g) := object.get(g, "stage", null)

agent_grants(g) := as_array(g, "grants")

agent_row_well_formed(g) if {
	is_object(g)
	lib.is_nonempty_string(agent_name(g))
	agent_stage(g) in stages_known
}

grant_action(gr) := object.get(gr, "action", null)

grant_row_well_formed(gr) if {
	is_object(gr)
	lib.is_nonempty_string(grant_action(gr))
}

grant_scopes(gr) := as_array(gr, "argumentScopes")

scope_parameter(sc) := object.get(sc, "parameter", null)

scope_pattern(sc) := object.get(sc, "pattern", null)

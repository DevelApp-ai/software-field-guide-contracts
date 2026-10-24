# Agent permission manifest gate — The Software Field Guide, issue #70.
#
# The kill-switch chapter's default-deny rule, enforced at the document
# level: the manifest is the allowlist, and the registry is what exists
# to be allowed. The gate fails loudly when the two disagree — a grant
# naming an action the registry never declared (manifest/action-unknown,
# the phantom grant), an argument scope constraining a parameter the
# action does not declare (manifest/argument-scope-undeclared), a
# read-only agent granted a write-effect action
# (manifest/stage-contradiction — the agent that can read and write
# will eventually do both in one reasoning chain), and a quarantined
# agent still carrying grants (manifest/quarantined-with-grants —
# quarantine means nothing runs). The scoping list renders the
# default-deny decision: each agent, its stage on the autonomy ladder,
# and the actions it may ask for.
#
# Input (JSON): {"registry": {...}, "manifest": {...}, "today": "YYYY-MM-DD"}
# Result:       {"valid": bool, "findings": [...], "scoping": [...]}
package actions

import rego.v1

import data.actions.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"scoping": scoping,
	}
}

gate_findings := ((((((f_input_invalid | f_today_invalid) | f_registry_missing) | f_manifest_missing) | f_manifest_stamps) | f_agents_shape) | f_grant_shape) | f_gate_grants

# --- findings: the manifest is missing ------------------------------------------

f_manifest_missing contains finding if {
	is_object(input)
	not is_object(manifest_doc)
	finding := {
		"severity": "error",
		"rule": "manifest/missing",
		"message": "the agent permission manifest is required: pass it as input.manifest — without an allowlist the default answer is no",
		"path": "$.manifest",
	}
}

# --- findings: the manifest's own stamps -------------------------------------------

# The manifest is a permission model expressed as data, versioned in
# configuration and reviewable like code: it needs an owner and a
# review cadence, or it drifts.
f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	not lib.is_nonempty_string(object.get(manifest_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "manifest/owner-required",
		"message": "the manifest must name an owner: permission data nobody owns is permission data nobody reviews",
		"path": "$.manifest.owner",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	not lib.is_valid_date(object.get(manifest_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "manifest/reviewed-on-invalid",
		"message": "the manifest must carry reviewedOn as a real YYYY-MM-DD date",
		"path": "$.manifest.reviewedOn",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	lib.is_valid_date(object.get(manifest_doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(manifest_doc, "reviewedOn", null)) > lib.date_to_days(object.get(input, "today", null))
	finding := {
		"severity": "error",
		"rule": "manifest/reviewed-in-future",
		"message": "the manifest carries a reviewedOn date in the future",
		"path": "$.manifest.reviewedOn",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	lib.is_valid_date(object.get(manifest_doc, "reviewedOn", null))
	lib.is_valid_date(object.get(input, "today", null))
	lib.date_to_days(object.get(input, "today", null)) - lib.date_to_days(object.get(manifest_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "manifest/reviewed-stale",
		"message": "the manifest was reviewed more than 365 days before today: this document is stale",
		"path": "$.manifest.reviewedOn",
	}
}

# --- findings: the agents and their stages ---------------------------------------------

f_agents_shape contains finding if {
	is_object(manifest_doc)
	not is_array(object.get(manifest_doc, "agents", null))
	finding := {
		"severity": "error",
		"rule": "agents/must-be-array",
		"message": "agents must be an array of {agent, stage, grants} entries",
		"path": "$.manifest.agents",
	}
}

f_agents_shape contains finding if {
	some i, g in as_array(manifest_doc, "agents")
	not is_object(g)
	finding := {
		"severity": "error",
		"rule": "agents/entry-must-be-object",
		"message": sprintf("agent entry %d must be an object with agent, stage, and grants", [i]),
		"path": sprintf("$.manifest.agents[%d]", [i]),
	}
}

f_agents_shape contains finding if {
	some i, g in agents
	not lib.is_nonempty_string(agent_name(g))
	finding := {
		"severity": "error",
		"rule": "agent/name-required",
		"message": sprintf("agent entry %d must carry a non-empty name: the grant is per agent, not per team, and it expires with the task", [i]),
		"path": sprintf("$.manifest.agents[%d].agent", [i]),
	}
}

f_agents_shape contains finding if {
	names := [agent_name(g) |
		some g in agents
		lib.is_nonempty_string(agent_name(g))
	]
	some name in names
	count([n | some n in names; n == name]) > 1
	finding := {
		"severity": "error",
		"rule": "agent/name-duplicate",
		"message": sprintf("agent '%s' appears more than once in the manifest: the circuit breaker is per agent — one agent must be one row", [name]),
		"path": "$.manifest.agents",
	}
}

# The staged autonomy ladder is a closed vocabulary: the rollback path
# is reviewable because the stages are named.
f_agents_shape contains finding if {
	some i, g in agents
	lib.is_nonempty_string(agent_name(g))
	not lib.is_nonempty_string(agent_stage(g))
	finding := {
		"severity": "error",
		"rule": "agent/stage-required",
		"message": sprintf("agent '%s' must declare its stage on the autonomy ladder: autonomous, propose-only, read-only, or quarantined", [agent_name(g)]),
		"path": sprintf("$.manifest.agents[%d].stage", [i]),
	}
}

f_agents_shape contains finding if {
	some i, g in agents
	lib.is_nonempty_string(agent_name(g))
	lib.is_nonempty_string(agent_stage(g))
	not agent_stage(g) in stages_known
	finding := {
		"severity": "error",
		"rule": "agent/stage-unknown",
		"message": sprintf("agent '%s' declares stage '%s', which is not on the staged autonomy ladder (%s)", [
			agent_name(g),
			agent_stage(g),
			concat(", ", sort(stages_known)),
		]),
		"path": sprintf("$.manifest.agents[%d].stage", [i]),
	}
}

f_agents_shape contains finding if {
	some i, g in agents
	lib.is_nonempty_string(agent_name(g))
	not is_array(object.get(g, "grants", null))
	finding := {
		"severity": "error",
		"rule": "grants/must-be-array",
		"message": sprintf("agent '%s' must carry grants as an array (an agent with no grants is a default-deny row, not a missing one)", [agent_name(g)]),
		"path": sprintf("$.manifest.agents[%d].grants", [i]),
	}
}

# --- findings: the grants and their argument scopes ---------------------------------------

f_grant_shape contains finding if {
	some i, g in agents
	some j, gr in as_array(g, "grants")
	not is_object(gr)
	finding := {
		"severity": "error",
		"rule": "grant/entry-must-be-object",
		"message": sprintf("grant %d of agent '%s' must be an object with action and argumentScopes", [j, agent_name(g)]),
		"path": sprintf("$.manifest.agents[%d].grants[%d]", [i, j]),
	}
}

f_grant_shape contains finding if {
	some i, g in agents
	some j, gr in agent_grants(g)
	is_object(gr)
	not lib.is_nonempty_string(grant_action(gr))
	finding := {
		"severity": "error",
		"rule": "grant/action-required",
		"message": sprintf("grant %d of agent '%s' must name the action it allows", [j, agent_name(g)]),
		"path": sprintf("$.manifest.agents[%d].grants[%d].action", [i, j]),
	}
}

f_grant_shape contains finding if {
	some i, g in agents
	actions_of_agent := [grant_action(gr) |
		some gr in agent_grants(g)
		grant_row_well_formed(gr)
	]
	some act in actions_of_agent
	count([x | some x in actions_of_agent; x == act]) > 1
	finding := {
		"severity": "error",
		"rule": "grant/duplicate",
		"message": sprintf("agent '%s' is granted action '%s' more than once: one grant is one permission — a duplicate is a scope nobody reviewed twice", [
			agent_name(g),
			act,
		]),
		"path": sprintf("$.manifest.agents[%d].grants", [i]),
	}
}

f_grant_shape contains finding if {
	some i, g in agents
	some j, gr in agent_grants(g)
	is_object(gr)
	some k, sc in grant_scopes(gr)
	not is_object(sc)
	finding := {
		"severity": "error",
		"rule": "scope/entry-must-be-object",
		"message": sprintf("argument scope %d of grant %d must be an object with parameter and pattern", [k, j]),
		"path": sprintf("$.manifest.agents[%d].grants[%d].argumentScopes[%d]", [i, j, k]),
	}
}

f_grant_shape contains finding if {
	some i, g in agents
	some j, gr in agent_grants(g)
	is_object(gr)
	some k, sc in grant_scopes(gr)
	is_object(sc)
	not lib.is_nonempty_string(scope_parameter(sc))
	finding := {
		"severity": "error",
		"rule": "scope/parameter-required",
		"message": sprintf("argument scope %d of grant %d must name the parameter it constrains: read_file on /etc and read_file on the task workspace are different permissions", [k, j]),
		"path": sprintf("$.manifest.agents[%d].grants[%d].argumentScopes[%d].parameter", [i, j, k]),
	}
}

f_grant_shape contains finding if {
	some i, g in agents
	some j, gr in agent_grants(g)
	is_object(gr)
	some k, sc in grant_scopes(gr)
	is_object(sc)
	not lib.is_nonempty_string(scope_pattern(sc))
	finding := {
		"severity": "error",
		"rule": "scope/pattern-required",
		"message": sprintf("argument scope %d of grant %d must carry its pattern: an argument scope without a boundary is the whole argument", [k, j]),
		"path": sprintf("$.manifest.agents[%d].grants[%d].argumentScopes[%d].pattern", [i, j, k]),
	}
}

# --- findings: the manifest must speak the registry's language -----------------------------

# The phantom grant — the issue's seeded contradiction. An allowlist
# entry naming an action the vocabulary never declared is a permission
# to something that does not exist: the default-deny answer to it is
# not a policy decision, it is a spelling correction.
f_gate_grants contains finding if {
	is_object(registry_doc)
	some i, g in agents
	some j, gr in agent_grants(g)
	grant_row_well_formed(gr)
	not grant_action(gr) in action_ids
	finding := {
		"severity": "error",
		"rule": "manifest/action-unknown",
		"message": sprintf("agent '%s' is granted action '%s', which the registry does not declare: the manifest and the registry disagree", [
			agent_name(g),
			grant_action(gr),
		]),
		"path": sprintf("$.manifest.agents[%d].grants[%d].action", [i, j]),
	}
}

# Argument-level permissions must constrain arguments that exist: a
# scope naming an undeclared parameter constrains nothing and audits
# less than that.
f_gate_grants contains finding if {
	is_object(registry_doc)
	some i, g in agents
	some j, gr in agent_grants(g)
	grant_row_well_formed(gr)
	grant_action(gr) in action_ids
	some k, sc in grant_scopes(gr)
	is_object(sc)
	lib.is_nonempty_string(scope_parameter(sc))
	not scope_parameter(sc) in action_parameter_names(action(grant_action(gr)))
	finding := {
		"severity": "error",
		"rule": "manifest/argument-scope-undeclared",
		"message": sprintf("agent '%s' scopes parameter '%s' of action '%s', which the action does not declare: the allowlist and the vocabulary disagree", [
			agent_name(g),
			scope_parameter(sc),
			grant_action(gr),
		]),
		"path": sprintf("$.manifest.agents[%d].grants[%d].argumentScopes[%d].parameter", [i, j, k]),
	}
}

# The staged ladder is a permission set, not a label: a read-only agent
# granted a write-effect action is the over-scoping the ladder exists
# to prevent — the capability is in the tool list and the plan looked
# plausible.
f_gate_grants contains finding if {
	is_object(registry_doc)
	some i, g in agents
	agent_row_well_formed(g)
	agent_stage(g) == "read-only"
	some j, gr in agent_grants(g)
	grant_row_well_formed(gr)
	grant_action(gr) in action_ids
	action_effect(action(grant_action(gr))) == "write"
	finding := {
		"severity": "error",
		"rule": "manifest/stage-contradiction",
		"message": sprintf("agent '%s' is read-only but is granted write action '%s': read-only is a permission set, not a label", [
			agent_name(g),
			grant_action(gr),
		]),
		"path": sprintf("$.manifest.agents[%d].grants[%d].action", [i, j]),
	}
}

# Quarantine means nothing runs: a quarantined agent still carrying
# grants is a breaker half-open.
f_gate_grants contains finding if {
	some i, g in agents
	agent_row_well_formed(g)
	agent_stage(g) == "quarantined"
	count(agent_grants(g)) > 0
	finding := {
		"severity": "error",
		"rule": "manifest/quarantined-with-grants",
		"message": sprintf("agent '%s' is quarantined but still carries %d grant(s): quarantine means nothing runs — grants wait for the stage to be lifted", [
			agent_name(g),
			count(agent_grants(g)),
		]),
		"path": sprintf("$.manifest.agents[%d].grants", [i]),
	}
}

# --- scoping: the default-deny decision the playground renders ------------------------------

# Per well-formed agent: its stage on the autonomy ladder and the
# actions it may ask for — well-formed grant ids only, deduplicated,
# sorted. An agent with no grants renders as the honest row it is:
# nothing allowed. The grants themselves are judged above; this list
# is what the boundary would answer, per agent, today.
scoping := sort([{
	"agent": agent_name(g),
	"stage": agent_stage(g),
	"actions": sort({grant_action(gr) |
		some gr in agent_grants(g)
		grant_row_well_formed(gr)
	}),
} |
	some g in agents
	agent_row_well_formed(g)
])

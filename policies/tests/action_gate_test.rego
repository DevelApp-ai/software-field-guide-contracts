package actions.gate_test

import rego.v1

import data.actions

import data.actions.fixture

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_good_manifest_passes if {
	r := actions.gate with input as fixture.gate_input(fixture.registry, fixture.manifest)
	r.valid == true
	count(r.findings) == 0
}

# The scoping list is the default-deny decision rendered: one row per
# agent, its stage, and the actions it may ask for.
test_scoping_renders_per_agent if {
	r := actions.gate with input as fixture.gate_input(fixture.registry, fixture.manifest)
	count(r.scoping) == 3
	row := [x | some x in r.scoping; x.agent == "invoice-drafting-agent"][0]
	row.stage == "autonomous"
	row.actions == ["fetch-invoice", "summarize-invoice"]
	chargeback := [x | some x in r.scoping; x.agent == "chargeback-agent"][0]
	chargeback.stage == "propose-only"
	chargeback.actions == ["file-draft-chargeback"]
	reader := [x | some x in r.scoping; x.agent == "archive-reader"][0]
	reader.stage == "read-only"
	reader.actions == ["fetch-invoice"]
}

test_scoping_renders_an_agent_with_no_grants if {
	# an agent with an empty grants list is a valid default-deny row —
	# the honest answer is nothing allowed, rendered as such
	m := object.union(fixture.manifest, {"agents": [
		object.union(fixture.manifest.agents[0], {"grants": []}),
		fixture.manifest.agents[1],
		fixture.manifest.agents[2],
	]})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	r.valid == true
	drafter := [x | some x in r.scoping; x.agent == "invoice-drafting-agent"][0]
	drafter.actions == []
}

test_input_must_be_object if {
	r := actions.gate with input as "nope"
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_missing_registry if {
	r := actions.gate with input as {"manifest": fixture.manifest, "today": fixture.today}
	not r.valid
	error_rules(r)["registry/missing"]

	# with no registry to speak of, the phantom-grant judgment stays
	# silent rather than flagging every grant as unknown
	not error_rules(r)["manifest/action-unknown"]
}

test_missing_manifest if {
	r := actions.gate with input as {"registry": fixture.registry, "today": fixture.today}
	not r.valid
	error_rules(r)["manifest/missing"]
}

# --- the manifest's own stamps ----------------------------------------------

test_manifest_owner_required if {
	m := object.remove(fixture.manifest, ["owner"])
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	error_rules(r)["manifest/owner-required"]
}

test_manifest_reviewed_on_invalid if {
	m := object.union(fixture.manifest, {"reviewedOn": "not-a-date"})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	error_rules(r)["manifest/reviewed-on-invalid"]
}

test_manifest_reviewed_in_future if {
	m := object.union(fixture.manifest, {"reviewedOn": "2026-10-21"})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	error_rules(r)["manifest/reviewed-in-future"]
}

test_manifest_reviewed_stale if {
	m := object.union(fixture.manifest, {"reviewedOn": "2025-10-19"})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	error_rules(r)["manifest/reviewed-stale"]
}

# --- agents and stages --------------------------------------------------------

test_agents_must_be_array if {
	m := object.remove(fixture.manifest, ["agents"])
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	error_rules(r)["agents/must-be-array"]
}

test_agent_stage_unknown if {
	m := fixture.with_agent_stage(fixture.manifest, "archive-reader", "mostly-harmless")
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	some f in r.findings
	f.rule == "agent/stage-unknown"
	contains(f.message, "autonomous, propose-only, quarantined, read-only")
}

test_agent_name_duplicate if {
	m := object.union(fixture.manifest, {"agents": array.concat(fixture.manifest.agents, [
		object.union(fixture.manifest.agents[0], {"stage": "read-only"}),
	])})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	error_rules(r)["agent/name-duplicate"]
}

test_grants_must_be_array if {
	m := object.union(fixture.manifest, {"agents": [object.remove(fixture.manifest.agents[0], ["grants"])]})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	error_rules(r)["grants/must-be-array"]
}

# --- grants and argument scopes --------------------------------------------------

# The issue's seeded manifest contradiction: a grant naming an action
# the registry never declared — the phantom grant.
test_phantom_grant_is_caught if {
	m := fixture.with_grant(fixture.manifest, "chargeback-agent", {
		"action": "purge-invoice-archive",
		"argumentScopes": [],
	})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	some f in r.findings
	f.rule == "manifest/action-unknown"
	f.path == "$.manifest.agents[1].grants[1].action"
	contains(f.message, "the manifest and the registry disagree")
}

test_argument_scope_must_name_a_declared_parameter if {
	m := fixture.with_grant(fixture.manifest, "invoice-drafting-agent", {
		"action": "fetch-invoice",
		"argumentScopes": [{"parameter": "orderId", "pattern": "ORD-*"}],
	})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	some f in r.findings
	f.rule == "manifest/argument-scope-undeclared"
	contains(f.message, "which the action does not declare")
}

test_scope_pattern_required if {
	m := fixture.with_grant(fixture.manifest, "invoice-drafting-agent", {
		"action": "fetch-invoice",
		"argumentScopes": [{"parameter": "invoiceId", "pattern": ""}],
	})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	error_rules(r)["scope/pattern-required"]
}

test_grant_duplicate if {
	m := fixture.with_grant(fixture.manifest, "invoice-drafting-agent", {
		"action": "fetch-invoice",
		"argumentScopes": [{"parameter": "invoiceId", "pattern": "INV-2026-*"}],
	})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	some f in r.findings
	f.rule == "grant/duplicate"
	contains(f.message, "a duplicate is a scope nobody reviewed twice")
}

# The issue's other seeded contradiction: a read-only agent granted a
# write-effect action.
test_readonly_agent_granted_write_action_is_caught if {
	m := fixture.with_grant(fixture.manifest, "archive-reader", {
		"action": "file-draft-chargeback",
		"argumentScopes": [{"parameter": "invoiceId", "pattern": "INV-*"}],
	})
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	some f in r.findings
	f.rule == "manifest/stage-contradiction"
	contains(f.message, "read-only is a permission set, not a label")
}

test_readonly_agent_with_read_actions_passes if {
	# the read-only stage allows read-effect actions — the contradiction
	# is the write effect, not the stage
	r := actions.gate with input as fixture.gate_input(fixture.registry, fixture.manifest)
	some row in r.scoping
	row.agent == "archive-reader"
	row.actions == ["fetch-invoice"]
}

test_propose_only_may_carry_write_grants if {
	# propose-only is the SpecTree default: everything becomes a PR
	# awaiting a human — write grants are the point of the stage
	r := actions.gate with input as fixture.gate_input(fixture.registry, fixture.manifest)
	some row in r.scoping
	row.agent == "chargeback-agent"
	row.actions == ["file-draft-chargeback"]
}

test_quarantined_agent_must_not_carry_grants if {
	m := fixture.with_agent_stage(fixture.manifest, "chargeback-agent", "quarantined")
	r := actions.gate with input as fixture.gate_input(fixture.registry, m)
	not r.valid
	some f in r.findings
	f.rule == "manifest/quarantined-with-grants"
	contains(f.message, "quarantine means nothing runs")
}

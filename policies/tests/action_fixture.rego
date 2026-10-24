# Shared fixture for the actions tests: one small, valid action registry
# and agent permission manifest in the storefront flavor of the book's
# examples — five micro-actions across all four execution families,
# two registered servers, platform ceilings, and three agents on
# three different rungs of the autonomy ladder.
#
# The review dates are chosen relative to the CI anchor date
# 2026-10-20.
package actions.fixture

import rego.v1

today := "2026-10-20"

registry := {
	"version": 1,
	"reviewedOn": "2026-10-01",
	"platformCeilings": {
		"maxTimeoutSeconds": 600,
		"maxMemoryMB": 2048,
	},
	"servers": [
		{
			"name": "invoice-service",
			"approved": true,
		},
		{
			"name": "courier-api",
			"approved": false,
		},
	],
	"actions": [
		{
			"id": "fetch-invoice",
			"name": "Fetch invoice",
			"description": "Retrieve one invoice record from the registered invoice service",
			"type": "ExternalServer",
			"parameters": [
				{"name": "invoiceId", "type": "string", "validation": {"minLength": 1}},
			],
			"outputs": {"invoice": "object"},
			"envelope": {"timeoutSeconds": 120, "maxMemoryMB": 512, "useIsolation": false},
			"securityLevel": "Low",
			"confirmation": "auto-confirm",
			"effect": "read",
			"server": {
				"name": "invoice-service",
				"operation": "getInvoice",
				"mappings": {"invoiceId": "invoiceId"},
			},
		},
		{
			"id": "summarize-invoice",
			"name": "Summarize invoice",
			"description": "Produce a plain-language summary of one invoice for the drafting agent",
			"type": "AgenticPrompt",
			"parameters": [
				{"name": "invoiceId", "type": "string", "validation": {"minLength": 1}},
			],
			"outputs": {"summary": "string"},
			"envelope": {"timeoutSeconds": 90, "maxMemoryMB": 256, "useIsolation": false},
			"securityLevel": "Low",
			"confirmation": "auto-confirm",
			"effect": "read",
		},
		{
			"id": "compile-quarterly-report",
			"name": "Compile quarterly report",
			"description": "Run the quarterly reporting script over the ledger in sidecar isolation",
			"type": "PythonScript",
			"parameters": [
				{"name": "quarter", "type": "string", "validation": {"enumValues": ["Q1", "Q2", "Q3", "Q4"]}},
			],
			"outputs": {"reportPath": "string"},
			"envelope": {"timeoutSeconds": 480, "maxMemoryMB": 1024, "useIsolation": true},
			"securityLevel": "Standard",
			"confirmation": "auto-confirm",
			"effect": "read",
		},
		{
			"id": "file-draft-chargeback",
			"name": "File draft chargeback",
			"description": "Draft a chargeback case for one disputed invoice and file it for review",
			"type": "CSharpScript",
			"parameters": [
				{"name": "invoiceId", "type": "string", "validation": {"minLength": 1}},
				{"name": "amount", "type": "number", "validation": {"minimum": 0}},
			],
			"outputs": {"caseId": "string"},
			"envelope": {"timeoutSeconds": 300, "maxMemoryMB": 1024, "useIsolation": true},
			"securityLevel": "High",
			"confirmation": "confirm",
			"effect": "write",
		},
		{
			"id": "send-invoice-email",
			"name": "Send invoice email",
			"description": "Send one invoice to one recipient through the registered invoice service",
			"type": "ExternalServer",
			"parameters": [
				{"name": "invoiceId", "type": "string", "validation": {"minLength": 1}},
				{"name": "recipient", "type": "string", "validation": {"minLength": 1}},
			],
			"outputs": {"messageId": "string"},
			"envelope": {"timeoutSeconds": 60, "maxMemoryMB": 256, "useIsolation": false},
			"securityLevel": "Critical",
			"confirmation": "confirm",
			"effect": "write",
			"server": {
				"name": "invoice-service",
				"operation": "sendInvoiceEmail",
				"mappings": {"invoiceId": "invoiceId", "recipient": "recipient"},
			},
		},
	],
}

manifest := {
	"owner": "Billing team",
	"reviewedOn": "2026-10-15",
	"agents": [
		{
			"agent": "invoice-drafting-agent",
			"stage": "autonomous",
			"grants": [
				{
					"action": "fetch-invoice",
					"argumentScopes": [{"parameter": "invoiceId", "pattern": "INV-*"}],
				},
				{
					"action": "summarize-invoice",
					"argumentScopes": [{"parameter": "invoiceId", "pattern": "INV-*"}],
				},
			],
		},
		{
			"agent": "chargeback-agent",
			"stage": "propose-only",
			"grants": [
				{
					"action": "file-draft-chargeback",
					"argumentScopes": [
						{"parameter": "invoiceId", "pattern": "INV-*"},
						{"parameter": "amount", "pattern": "*"},
					],
				},
			],
		},
		{
			"agent": "archive-reader",
			"stage": "read-only",
			"grants": [
				{
					"action": "fetch-invoice",
					"argumentScopes": [{"parameter": "invoiceId", "pattern": "INV-2026-*"}],
				},
			],
		},
	],
}

validate_input(registry_doc) := {
	"registry": registry_doc,
	"today": today,
}

gate_input(registry_doc, manifest_doc) := {
	"registry": registry_doc,
	"manifest": manifest_doc,
	"today": today,
}

# --- registry override helpers ------------------------------------------------
#
# The #69 lesson, applied: an array comprehension with a condition in
# the body filters, so per-element overrides go through explicit
# two-definition helpers that always answer — the row itself when it
# does not match, the patched row when it does.

# Field replacement, not merge: object.union deep-merges object values,
# so a patch that means "this object is now X" removes the key first.
replace_field(obj, patch) := object.union(object.remove(obj, object.keys(patch)), patch)

# Override one top-level field of one action, by action id.
with_action_field(registry_doc, id, patch) := object.union(registry_doc, {
	"actions": [action_field_override(a, id, patch) |
		some a in registry_doc.actions
	],
})

action_field_override(a, id, patch) := replace_field(a, patch) if object.get(a, "id", null) == id

action_field_override(a, id, patch) := a if object.get(a, "id", null) != id

# Override one field of one parameter of one action.
with_parameter_field(registry_doc, action_id, parameter_name, patch) := object.union(registry_doc, {
	"actions": [parameter_field_override(a, action_id, parameter_name, patch) |
		some a in registry_doc.actions
	],
})

parameter_field_override(a, action_id, parameter_name, patch) := replace_field(a, {
	"parameters": [parameter_patch_override(p, parameter_name, patch) |
		some p in a.parameters
	],
}) if object.get(a, "id", null) == action_id

parameter_field_override(a, action_id, parameter_name, patch) := a if object.get(a, "id", null) != action_id

parameter_patch_override(p, parameter_name, patch) := replace_field(p, patch) if object.get(p, "name", null) == parameter_name

parameter_patch_override(p, parameter_name, patch) := p if object.get(p, "name", null) != parameter_name

# Override one field of one action's execution envelope.
with_envelope_field(registry_doc, id, patch) := object.union(registry_doc, {
	"actions": [envelope_field_override(a, id, patch) |
		some a in registry_doc.actions
	],
})

envelope_field_override(a, id, patch) := replace_field(a, {
	"envelope": replace_field(object.get(a, "envelope", {}), patch),
}) if object.get(a, "id", null) == id

envelope_field_override(a, id, patch) := a if object.get(a, "id", null) != id

# --- manifest override helpers --------------------------------------------------

# Add one grant to one agent, by agent name.
with_grant(manifest_doc, agent_name, grant) := object.union(manifest_doc, {
	"agents": [agent_grant_override(g, agent_name, grant) |
		some g in manifest_doc.agents
	],
})

agent_grant_override(g, agent_name, grant) := replace_field(g, {
	"grants": array.concat(g.grants, [grant]),
}) if object.get(g, "agent", null) == agent_name

agent_grant_override(g, agent_name, grant) := g if object.get(g, "agent", null) != agent_name

# Override one agent's stage on the autonomy ladder.
with_agent_stage(manifest_doc, agent_name, stage) := object.union(manifest_doc, {
	"agents": [agent_stage_override(g, agent_name, stage) |
		some g in manifest_doc.agents
	],
})

agent_stage_override(g, agent_name, stage) := replace_field(g, {"stage": stage}) if object.get(g, "agent", null) == agent_name

agent_stage_override(g, agent_name, stage) := g if object.get(g, "agent", null) != agent_name

package actions.policy_test

import rego.v1

import data.actions

import data.actions.fixture

import data.actions.lib

error_rules(r) := {f.rule | some f in r.findings; f.severity == "error"}

test_valid_registry_passes if {
	r := actions.validate with input as fixture.validate_input(fixture.registry)
	r.valid == true
	count(r.findings) == 0
}

test_input_must_be_object if {
	r := actions.validate with input as [1, 2]
	not r.valid
	r.findings[0].rule == "input/invalid"
}

test_today_invalid if {
	r := actions.validate with input as {"registry": fixture.registry, "today": "yesterday"}
	not r.valid
	error_rules(r)["input/today-invalid"]
}

test_missing_registry if {
	r := actions.validate with input as {"today": fixture.today}
	not r.valid
	error_rules(r)["registry/missing"]
}

# --- stamps -------------------------------------------------------------------

test_version_required if {
	reg := object.remove(fixture.registry, ["version"])
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["registry/version-required"]
}

test_reviewed_on_invalid if {
	reg := object.union(fixture.registry, {"reviewedOn": "2026-02-30"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["registry/reviewed-on-invalid"]
}

test_reviewed_in_future if {
	reg := object.union(fixture.registry, {"reviewedOn": "2026-10-21"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["registry/reviewed-in-future"]
}

test_reviewed_stale if {
	reg := object.union(fixture.registry, {"reviewedOn": "2025-10-19"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["registry/reviewed-stale"]
}

# --- platform ceilings -----------------------------------------------------------

test_ceilings_required if {
	reg := object.remove(fixture.registry, ["platformCeilings"])
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["registry/ceilings-required"]

	# without declared ceilings no envelope breach can be judged — but the
	# breach judgment simply stays silent, it does not error
	not error_rules(r)["envelope/exceeds-ceiling"]
}

test_ceiling_timeout_invalid if {
	reg := object.union(fixture.registry, {"platformCeilings": {"maxTimeoutSeconds": "soon", "maxMemoryMB": 2048}})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["registry/ceiling-timeout-invalid"]
}

test_ceiling_memory_invalid if {
	reg := object.union(fixture.registry, {"platformCeilings": {"maxTimeoutSeconds": 600, "maxMemoryMB": 0}})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["registry/ceiling-memory-invalid"]
}

# --- registered servers -----------------------------------------------------------

test_servers_must_be_array if {
	reg := object.remove(fixture.registry, ["servers"])
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["servers/must-be-array"]
}

test_server_name_required if {
	reg := object.union(fixture.registry, {"servers": [{"name": "", "approved": true}]})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "server/name-required"
	f.path == "$.registry.servers[0].name"
}

test_server_approved_must_be_boolean if {
	reg := object.union(fixture.registry, {"servers": [{"name": "ghost-service", "approved": "yes"}]})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["server/approved-required"]
}

test_server_name_duplicate if {
	reg := object.union(fixture.registry, {"servers": array.concat(fixture.registry.servers, [
		{"name": "invoice-service", "approved": true},
	])})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["server/name-duplicate"]
}

# --- the actions array ---------------------------------------------------------------

test_actions_must_be_array if {
	reg := object.remove(fixture.registry, ["actions"])
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["actions/must-be-array"]
}

test_actions_required if {
	reg := object.union(fixture.registry, {"actions": []})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["actions/required"]
}

test_action_id_required if {
	reg := object.union(fixture.registry, {"actions": array.concat(fixture.registry.actions, [
		{"id": "", "name": "Ghost", "description": "An action with no id"},
	])})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "action/id-required"
	f.path == "$.registry.actions[5].id"
}

test_action_id_duplicate if {
	reg := object.union(fixture.registry, {"actions": array.concat(fixture.registry.actions, [
		object.union(fixture.registry.actions[0], {"name": "Fetch invoice again"}),
	])})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/id-duplicate"]
}

test_action_name_required if {
	reg := fixture.with_action_field(fixture.registry, "fetch-invoice", {"name": ""})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/name-required"]
}

test_action_description_required if {
	reg := fixture.with_action_field(fixture.registry, "fetch-invoice", {"description": "  "})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/description-required"]
}

# --- type: the execution family ---------------------------------------------------------

test_type_required if {
	reg := fixture.with_action_field(fixture.registry, "summarize-invoice", {"type": ""})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/type-required"]
}

test_type_unknown if {
	reg := fixture.with_action_field(fixture.registry, "summarize-invoice", {"type": "ShellScript"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "action/type-unknown"
	contains(f.message, "ShellScript")
	contains(f.message, "AgenticPrompt, CSharpScript, ExternalServer, PythonScript")
}

# --- parameters: the typed, checked schema ------------------------------------------------

test_parameters_must_be_array if {
	reg := fixture.with_action_field(fixture.registry, "fetch-invoice", {"parameters": {"invoiceId": "string"}})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/parameters-must-be-array"]
}

# The issue's own headline: an action that skips its parameter checks
# ships if a reviewer misses it — the seeded untyped parameter.
test_parameter_untyped if {
	reg := fixture.with_parameter_field(fixture.registry, "fetch-invoice", "invoiceId", {"type": ""})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "action/parameter-untyped"
	f.path == "$.registry.actions[0].parameters[0].type"
	contains(f.message, "an untyped parameter is a parameter nobody checks")
}

test_parameter_type_unknown if {
	reg := fixture.with_parameter_field(fixture.registry, "fetch-invoice", "invoiceId", {"type": "filepath"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/parameter-type-unknown"]
}

test_parameter_validation_required if {
	reg := fixture.with_parameter_field(fixture.registry, "fetch-invoice", "invoiceId", {"validation": null})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/parameter-validation-required"]
}

test_parameter_enum_values_must_be_an_array if {
	reg := fixture.with_parameter_field(fixture.registry, "compile-quarterly-report", "quarter", {
		"validation": {"enumValues": "Q1, Q2, Q3, Q4"},
	})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/parameter-enum-values-required"]
}

test_parameter_enum_values_must_not_be_empty if {
	reg := fixture.with_parameter_field(fixture.registry, "compile-quarterly-report", "quarter", {
		"validation": {"enumValues": []},
	})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/parameter-enum-values-required"]
}

test_parameter_name_duplicate if {
	reg := fixture.with_action_field(fixture.registry, "fetch-invoice", {"parameters": array.concat(
		fixture.registry.actions[0].parameters,
		[{"name": "invoiceId", "type": "string", "validation": {"minLength": 1}}],
	)})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/parameter-name-duplicate"]
}

# --- outputs: the declared result shape --------------------------------------------------------

test_outputs_required if {
	reg := fixture.with_action_field(fixture.registry, "summarize-invoice", {"outputs": {}})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/outputs-required"]
}

# --- the execution envelope ---------------------------------------------------------------------

test_envelope_required if {
	reg := fixture.with_action_field(fixture.registry, "summarize-invoice", {"envelope": "whenever"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["envelope/invalid"]
}

test_envelope_timeout_required if {
	reg := fixture.with_envelope_field(fixture.registry, "summarize-invoice", {"timeoutSeconds": 0})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["envelope/timeout-required"]
}

test_envelope_memory_required if {
	reg := fixture.with_envelope_field(fixture.registry, "summarize-invoice", {"maxMemoryMB": "plenty"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["envelope/memory-required"]
}

# The issue's seeded envelope violation: a declared timeout past the
# platform ceiling.
test_envelope_exceeds_timeout_ceiling if {
	reg := fixture.with_envelope_field(fixture.registry, "compile-quarterly-report", {"timeoutSeconds": 900})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "envelope/exceeds-ceiling"
	f.path == "$.registry.actions[2].envelope.timeoutSeconds"
	contains(f.message, "past the platform ceiling of 600")
}

test_envelope_exceeds_memory_ceiling if {
	reg := fixture.with_envelope_field(fixture.registry, "compile-quarterly-report", {"maxMemoryMB": 4096})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "envelope/exceeds-ceiling"
	contains(f.message, "past the platform ceiling of 2048")
}

test_scripted_action_requires_isolation if {
	reg := fixture.with_envelope_field(fixture.registry, "compile-quarterly-report", {"useIsolation": false})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "envelope/isolation-required"
	contains(f.message, "scripted actions run in sidecar isolation")
}

test_prompt_action_does_not_demand_isolation if {
	# AgenticPrompt work stays inside the agent loop — no sidecar needed,
	# and demanding one would be noise, not safety
	reg := fixture.with_envelope_field(fixture.registry, "summarize-invoice", {"useIsolation": false})
	r := actions.validate with input as fixture.validate_input(reg)
	r.valid == true
}

# --- security level, confirmation, effect --------------------------------------------------------

test_security_level_required if {
	reg := fixture.with_action_field(fixture.registry, "file-draft-chargeback", {"securityLevel": ""})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/security-level-required"]
}

test_security_level_unknown if {
	reg := fixture.with_action_field(fixture.registry, "file-draft-chargeback", {"securityLevel": "Very-High"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/security-level-unknown"]
}

test_confirmation_required if {
	reg := fixture.with_action_field(fixture.registry, "file-draft-chargeback", {"confirmation": ""})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/confirmation-required"]
}

test_confirmation_unknown if {
	reg := fixture.with_action_field(fixture.registry, "file-draft-chargeback", {"confirmation": "ask-politely"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/confirmation-unknown"]
}

# The issue's second seeded violation: auto-confirm past the gate's
# classification on a Critical action.
test_critical_action_must_demand_confirmation if {
	reg := fixture.with_action_field(fixture.registry, "send-invoice-email", {"confirmation": "auto-confirm"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "action/confirm-required-at-level"
	f.path == "$.registry.actions[4].confirmation"
	contains(f.message, "auto-confirm past the gate's classification is the failure mode")
}

test_high_action_must_demand_confirmation if {
	reg := fixture.with_action_field(fixture.registry, "file-draft-chargeback", {"confirmation": "auto-confirm"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/confirm-required-at-level"]
}

test_low_action_may_auto_confirm if {
	reg := fixture.with_action_field(fixture.registry, "summarize-invoice", {"confirmation": "auto-confirm"})
	r := actions.validate with input as fixture.validate_input(reg)
	r.valid == true
}

test_effect_required if {
	reg := fixture.with_action_field(fixture.registry, "file-draft-chargeback", {"effect": ""})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/effect-required"]
}

test_effect_unknown if {
	reg := fixture.with_action_field(fixture.registry, "file-draft-chargeback", {"effect": "maybe"})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/effect-unknown"]
}

# --- external server references ---------------------------------------------------------------------

test_external_action_requires_a_server if {
	reg := fixture.with_action_field(fixture.registry, "send-invoice-email", {"server": null})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/server-required"]
}

test_external_action_server_must_be_registered if {
	reg := fixture.with_action_field(fixture.registry, "send-invoice-email", {
		"server": {"name": "public-webhook", "operation": "post", "mappings": {}},
	})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "action/server-unknown"
	contains(f.message, "public-webhook")
}

test_external_action_server_must_be_approved if {
	reg := fixture.with_action_field(fixture.registry, "send-invoice-email", {
		"server": {"name": "courier-api", "operation": "send", "mappings": {}},
	})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	some f in r.findings
	f.rule == "action/server-unapproved"
	contains(f.message, "registered but not approved")
}

test_external_action_requires_operation_and_mappings if {
	reg := fixture.with_action_field(fixture.registry, "fetch-invoice", {
		"server": {"name": "invoice-service"},
	})
	r := actions.validate with input as fixture.validate_input(reg)
	not r.valid
	error_rules(r)["action/server-operation-required"]
	error_rules(r)["action/server-mappings-required"]
}

test_local_action_does_not_demand_a_server if {
	# a scripted action with a stray server key is odd but not a boundary
	# question — the server rules judge ExternalServer actions only
	reg := fixture.with_action_field(fixture.registry, "compile-quarterly-report", {
		"server": {"name": "nowhere", "operation": "x", "mappings": {}},
	})
	r := actions.validate with input as fixture.validate_input(reg)
	r.valid == true
}

# --- lib parity: the date helpers are a verbatim copy of the estate lib ------

test_epoch_is_day_zero if {
	lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	lib.date_to_days("2026-10-20") - lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not lib.is_valid_date("2026-02-30")
}

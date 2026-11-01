# The citizen app manifest validated alone — The Software Field
# Guide, issue #84.
#
# Every finding below judges ONE document: the citizen app manifest,
# the citizen-built app recorded as data — its components and the
# behavior each declares, the data bindings it opens, the platform
# actions it uses, and the guardrails it builds against with their
# versions. The validator models a stated subset honestly — binding
# form (a name, a read or write mode, a rail to ride), action
# strings, guardrail names and versions — not the full semantics of
# any real low-code platform. The joins live in the gate: an escape
# hatch, an action outside the spec's rails, a behavior without
# coverage, a guardrail below the platform floor are all judged
# where the manifest meets the spec and the registry.
package citizen

import rego.v1

import data.citizen.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_findings := ((((((((((f_input_invalid | f_today_invalid) | f_manifest_missing) | f_manifest_stamps) | f_components_shape) | f_components_content) | f_bindings_shape) | f_bindings_content) | f_actions_shape) | f_actions_content) | f_guardrails_shape) | f_guardrails_content

# --- findings: the input and the clock -----------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the citizen app manifest as input.manifest",
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

# --- findings: the manifest document --------------------------------------------

f_manifest_missing contains finding if {
	not is_object(manifest_doc)
	finding := {
		"severity": "error",
		"rule": "manifest/missing",
		"message": "the citizen app manifest is required: pass it as input.manifest",
		"path": "$.manifest",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	not is_positive_integer(object.get(manifest_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "manifest/version-required",
		"message": sprintf("the app manifest must carry a version (a positive integer): the app's posture is versioned like the app (%s)", [manifest_file]),
		"path": "$.manifest.version",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	not lib.is_valid_date(object.get(manifest_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "manifest/reviewed-on-invalid",
		"message": sprintf("the app manifest must carry reviewedOn as a real YYYY-MM-DD date (%s)", [manifest_file]),
		"path": "$.manifest.reviewedOn",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	lib.is_valid_date(object.get(manifest_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(manifest_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "manifest/reviewed-in-future",
		"message": sprintf("the app manifest carries a reviewedOn date in the future (%s)", [manifest_file]),
		"path": "$.manifest.reviewedOn",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	lib.is_valid_date(object.get(manifest_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(manifest_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "manifest/reviewed-stale",
		"message": sprintf("the app manifest was reviewed more than 365 days before today: this manifest says nothing about the app that changed since (%s)", [manifest_file]),
		"path": "$.manifest.reviewedOn",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	not lib.is_nonempty_string(object.get(manifest_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "manifest/owner-required",
		"message": sprintf("the app manifest must name an owner: a citizen app with an owner and a review cadence is the discipline (%s)", [manifest_file]),
		"path": "$.manifest.owner",
	}
}

f_manifest_stamps contains finding if {
	is_object(manifest_doc)
	not lib.is_nonempty_string(object.get(manifest_doc, "app", null))
	finding := {
		"severity": "error",
		"rule": "manifest/app-required",
		"message": sprintf("the app manifest must name the app it describes: advice lands on an app, not on a file (%s)", [manifest_file]),
		"path": "$.manifest.app",
	}
}

# --- findings: the components ----------------------------------------------------

f_components_shape contains finding if {
	is_object(manifest_doc)
	not is_array(object.get(manifest_doc, "components", null))
	finding := {
		"severity": "error",
		"rule": "components/must-be-array",
		"message": sprintf("the app manifest's components must be an array of {name, behavior} rows (%s)", [manifest_file]),
		"path": "$.manifest.components",
	}
}

f_components_shape contains finding if {
	is_object(manifest_doc)
	is_array(object.get(manifest_doc, "components", null))
	some c in object.get(manifest_doc, "components", [])
	not is_object(c)
	finding := {
		"severity": "error",
		"rule": "components/row-must-be-object",
		"message": sprintf("every component row must be an object: {name, behavior} (%s)", [manifest_file]),
		"path": "$.manifest.components",
	}
}

f_components_content contains finding if {
	some c in components
	not lib.is_nonempty_string(component_name(c))
	finding := {
		"severity": "error",
		"rule": "component/name-required",
		"message": sprintf("every component must carry a non-empty name (%s)", [manifest_file]),
		"path": "$.manifest.components",
	}
}

f_components_content contains finding if {
	some c in components
	not lib.is_nonempty_string(component_behavior(c))
	finding := {
		"severity": "error",
		"rule": "component/behavior-required",
		"message": sprintf("every component must declare its behavior in a non-empty string: behavior without a name is coverage nobody can check (%s)", [manifest_file]),
		"path": "$.manifest.components",
	}
}

# --- findings: the data bindings ---------------------------------------------------

f_bindings_shape contains finding if {
	is_object(manifest_doc)
	not is_array(object.get(manifest_doc, "dataBindings", null))
	finding := {
		"severity": "error",
		"rule": "bindings/must-be-array",
		"message": sprintf("the app manifest's dataBindings must be an array of {name, mode, via} rows (%s)", [manifest_file]),
		"path": "$.manifest.dataBindings",
	}
}

f_bindings_shape contains finding if {
	is_object(manifest_doc)
	is_array(object.get(manifest_doc, "dataBindings", null))
	some b in object.get(manifest_doc, "dataBindings", [])
	not is_object(b)
	finding := {
		"severity": "error",
		"rule": "bindings/row-must-be-object",
		"message": sprintf("every data binding row must be an object: {name, mode, via} (%s)", [manifest_file]),
		"path": "$.manifest.dataBindings",
	}
}

f_bindings_content contains finding if {
	some b in bindings
	not lib.is_nonempty_string(binding_name(b))
	finding := {
		"severity": "error",
		"rule": "binding/name-required",
		"message": sprintf("every data binding must carry a non-empty name: advice names the binding it lands on (%s)", [manifest_file]),
		"path": "$.manifest.dataBindings",
	}
}

f_bindings_content contains finding if {
	some b in bindings
	not binding_mode_valid(binding_mode(b))
	finding := {
		"severity": "error",
		"rule": "binding/mode-unknown",
		"message": sprintf("every data binding must declare its mode as read or write — '%v' is a mode the linter never agreed to model (%s)", [binding_mode(b), manifest_file]),
		"path": "$.manifest.dataBindings",
	}
}

f_bindings_content contains finding if {
	some b in bindings
	not lib.is_nonempty_string(binding_via(b))
	finding := {
		"severity": "error",
		"rule": "binding/via-required",
		"message": sprintf("every data binding must name the rail it rides via: the gate judges the rail against the registry, but an unnamed rail is not a rail (%s)", [manifest_file]),
		"path": "$.manifest.dataBindings",
	}
}

# --- findings: the actions used ------------------------------------------------------

f_actions_shape contains finding if {
	is_object(manifest_doc)
	not is_array(object.get(manifest_doc, "actions", null))
	finding := {
		"severity": "error",
		"rule": "actions/must-be-array",
		"message": sprintf("the app manifest's actions must be an array of the platform action names the app uses (%s)", [manifest_file]),
		"path": "$.manifest.actions",
	}
}

f_actions_shape contains finding if {
	is_object(manifest_doc)
	is_array(object.get(manifest_doc, "actions", null))
	some a in object.get(manifest_doc, "actions", [])
	not is_string(a)
	finding := {
		"severity": "error",
		"rule": "actions/row-must-be-string",
		"message": sprintf("every action entry must be a string: the platform action names the spec grants or withholds (%s)", [manifest_file]),
		"path": "$.manifest.actions",
	}
}

f_actions_content contains finding if {
	some a in actions
	not lib.is_nonempty_string(a)
	finding := {
		"severity": "error",
		"rule": "action/name-required",
		"message": sprintf("every action the app uses must be a non-empty name (%s)", [manifest_file]),
		"path": "$.manifest.actions",
	}
}

f_actions_content contains finding if {
	some a in actions
	f := count([x | some x in actions; x == a])
	f > 1
	finding := {
		"severity": "error",
		"rule": "action/name-duplicate",
		"message": sprintf("the action '%s' is declared more than once: one use, one row (%s)", [a, manifest_file]),
		"path": "$.manifest.actions",
	}
}

# --- findings: the guardrails it builds against ----------------------------------------

f_guardrails_shape contains finding if {
	is_object(manifest_doc)
	not is_array(object.get(manifest_doc, "guardrails", null))
	finding := {
		"severity": "error",
		"rule": "guardrails/must-be-array",
		"message": sprintf("the app manifest's guardrails must be an array of {name, version} rows (%s)", [manifest_file]),
		"path": "$.manifest.guardrails",
	}
}

f_guardrails_shape contains finding if {
	is_object(manifest_doc)
	is_array(object.get(manifest_doc, "guardrails", null))
	some g in object.get(manifest_doc, "guardrails", [])
	not is_object(g)
	finding := {
		"severity": "error",
		"rule": "guardrails/row-must-be-object",
		"message": sprintf("every guardrail row must be an object: {name, version} (%s)", [manifest_file]),
		"path": "$.manifest.guardrails",
	}
}

f_guardrails_content contains finding if {
	some g in guardrails
	not lib.is_nonempty_string(guardrail_name(g))
	finding := {
		"severity": "error",
		"rule": "guardrail/name-required",
		"message": sprintf("every guardrail must carry a non-empty name: the registry declares floors by name (%s)", [manifest_file]),
		"path": "$.manifest.guardrails",
	}
}

f_guardrails_content contains finding if {
	some g in guardrails
	not is_positive_integer(guardrail_version(g))
	finding := {
		"severity": "error",
		"rule": "guardrail/version-required",
		"message": sprintf("every guardrail must carry a version (a positive integer): the gate judges versions against the platform floor (%s)", [manifest_file]),
		"path": "$.manifest.guardrails",
	}
}

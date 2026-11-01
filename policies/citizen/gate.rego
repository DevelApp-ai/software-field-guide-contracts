# Citizen spec-rails gate — The Software Field Guide, issue #84.
#
# The manifest declares the app; the spec grants its rails; the
# registry holds the platform's floors. This gate joins the three
# documents and advises — advisor, not blocker, at the citizen's PR
# gate. The four drifts the gate knows by name, all advisories that
# keep the gate green while putting the advice on the record: an
# escape hatch (a data binding that goes around the rails the
# registry declares), an action outside the spec's rails, a
# component behavior the spec's coverage never declares, and a
# guardrail built below the platform floor. A guardrail the registry
# never heard of advises too. What fails the gate is a document the
# advisor cannot read — a manifest, spec, or registry with broken
# stamps or shapes is a question the advisor refuses to answer on
# its own inputs, the only red the advisor can show. The advice
# cards render the whole board: one row per judged item across the
# four areas, aligned or advises.
#
# Input (JSON): {"manifest": {...}, "spec": {...}, "registry": {...},
#                "today": "YYYY-MM-DD", "manifestFile": "...",
#                "specFile": "...", "registryFile": "..."}
# Result:       {"valid": bool, "findings": [...], "cards": [...], "verdict": "..."}
package citizen

import rego.v1

import data.citizen.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"cards": advice_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := validate_findings | (((((((((g_spec_missing | g_spec_stamps) | g_spec_shape) | g_registry_missing) | g_registry_stamps) | g_registry_shape) | g_escape_hatch) | g_action_outside) | g_behavior_uncovered) | g_guardrail_floors)

# --- findings: the spec document at the gate ----------------------------------

g_spec_missing contains finding if {
	not is_object(spec_doc)
	finding := {
		"severity": "error",
		"rule": "spec/missing",
		"message": "the app spec is required at the gate: pass it as input.spec — the rails are the spec's word, not the app's",
		"path": "$.spec",
	}
}

g_spec_stamps contains finding if {
	is_object(spec_doc)
	not is_positive_integer(object.get(spec_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "spec/version-required",
		"message": sprintf("the app spec must carry a version (a positive integer): rails are versioned like the app they govern (%s)", [spec_file]),
		"path": "$.spec.version",
	}
}

g_spec_stamps contains finding if {
	is_object(spec_doc)
	not lib.is_valid_date(object.get(spec_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "spec/reviewed-on-invalid",
		"message": sprintf("the app spec must carry reviewedOn as a real YYYY-MM-DD date (%s)", [spec_file]),
		"path": "$.spec.reviewedOn",
	}
}

g_spec_stamps contains finding if {
	is_object(spec_doc)
	lib.is_valid_date(object.get(spec_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(spec_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "spec/reviewed-in-future",
		"message": sprintf("the app spec carries a reviewedOn date in the future (%s)", [spec_file]),
		"path": "$.spec.reviewedOn",
	}
}

g_spec_stamps contains finding if {
	is_object(spec_doc)
	not lib.is_nonempty_string(object.get(spec_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "spec/owner-required",
		"message": sprintf("the app spec must name an owner: rails without an owner are rails nobody maintains (%s)", [spec_file]),
		"path": "$.spec.owner",
	}
}

# --- findings: the spec's rails and coverage -----------------------------------

g_spec_shape contains finding if {
	is_object(spec_doc)
	not is_array(object.get(spec_doc, "actions", null))
	finding := {
		"severity": "error",
		"rule": "rails/must-be-array",
		"message": sprintf("the app spec's actions must be an array of the platform actions the rails grant (%s)", [spec_file]),
		"path": "$.spec.actions",
	}
}

g_spec_shape contains finding if {
	is_object(spec_doc)
	is_array(object.get(spec_doc, "actions", null))
	some a in object.get(spec_doc, "actions", [])
	not is_string(a)
	finding := {
		"severity": "error",
		"rule": "rails/row-must-be-string",
		"message": sprintf("every rail entry must be a string: the platform action names the spec grants (%s)", [spec_file]),
		"path": "$.spec.actions",
	}
}

g_spec_shape contains finding if {
	is_object(spec_doc)
	not is_array(object.get(spec_doc, "coverage", null))
	finding := {
		"severity": "error",
		"rule": "coverage/must-be-array",
		"message": sprintf("the app spec's coverage must be an array of the behaviors the spec declares (%s)", [spec_file]),
		"path": "$.spec.coverage",
	}
}

g_spec_shape contains finding if {
	is_object(spec_doc)
	is_array(object.get(spec_doc, "coverage", null))
	some b in object.get(spec_doc, "coverage", [])
	not is_string(b)
	finding := {
		"severity": "error",
		"rule": "coverage/row-must-be-string",
		"message": sprintf("every coverage entry must be a string: a behavior the spec declares (%s)", [spec_file]),
		"path": "$.spec.coverage",
	}
}

# --- findings: the registry document at the gate -------------------------------

g_registry_missing contains finding if {
	not is_object(registry_doc)
	finding := {
		"severity": "error",
		"rule": "registry/missing",
		"message": "the platform guardrail registry is required at the gate: pass it as input.registry — the rails and the floors are the platform's word, not the app's",
		"path": "$.registry",
	}
}

g_registry_stamps contains finding if {
	is_object(registry_doc)
	not is_positive_integer(object.get(registry_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "registry/version-required",
		"message": sprintf("the platform guardrail registry must carry a version (a positive integer): floors are versioned like the platform that sets them (%s)", [registry_file]),
		"path": "$.registry.version",
	}
}

g_registry_stamps contains finding if {
	is_object(registry_doc)
	not lib.is_valid_date(object.get(registry_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "registry/reviewed-on-invalid",
		"message": sprintf("the platform guardrail registry must carry reviewedOn as a real YYYY-MM-DD date (%s)", [registry_file]),
		"path": "$.registry.reviewedOn",
	}
}

g_registry_stamps contains finding if {
	is_object(registry_doc)
	lib.is_valid_date(object.get(registry_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(registry_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "registry/reviewed-in-future",
		"message": sprintf("the platform guardrail registry carries a reviewedOn date in the future (%s)", [registry_file]),
		"path": "$.registry.reviewedOn",
	}
}

g_registry_stamps contains finding if {
	is_object(registry_doc)
	not lib.is_nonempty_string(object.get(registry_doc, "owner", null))
	finding := {
		"severity": "error",
		"rule": "registry/owner-required",
		"message": sprintf("the platform guardrail registry must name an owner: floors without an owner are floors nobody raises (%s)", [registry_file]),
		"path": "$.registry.owner",
	}
}

# --- findings: the registry's rails and floors ----------------------------------

g_registry_shape contains finding if {
	is_object(registry_doc)
	not is_array(object.get(registry_doc, "dataRails", null))
	finding := {
		"severity": "error",
		"rule": "datarails/must-be-array",
		"message": sprintf("the registry's dataRails must be an array of the rails a binding may ride (%s)", [registry_file]),
		"path": "$.registry.dataRails",
	}
}

g_registry_shape contains finding if {
	is_object(registry_doc)
	is_array(object.get(registry_doc, "dataRails", null))
	some r in object.get(registry_doc, "dataRails", [])
	not is_string(r)
	finding := {
		"severity": "error",
		"rule": "datarails/row-must-be-string",
		"message": sprintf("every dataRail entry must be a string: the rail a binding rides (%s)", [registry_file]),
		"path": "$.registry.dataRails",
	}
}

g_registry_shape contains finding if {
	is_object(registry_doc)
	not is_array(object.get(registry_doc, "platformFloor", null))
	finding := {
		"severity": "error",
		"rule": "platformfloor/must-be-array",
		"message": sprintf("the registry's platformFloor must be an array of {name, floor} rows (%s)", [registry_file]),
		"path": "$.registry.platformFloor",
	}
}

g_registry_shape contains finding if {
	is_object(registry_doc)
	is_array(object.get(registry_doc, "platformFloor", null))
	some f in object.get(registry_doc, "platformFloor", [])
	not is_object(f)
	finding := {
		"severity": "error",
		"rule": "platformfloor/row-must-be-object",
		"message": sprintf("every platformFloor row must be an object: {name, floor} (%s)", [registry_file]),
		"path": "$.registry.platformFloor",
	}
}

g_registry_shape contains finding if {
	some f in floors
	not lib.is_nonempty_string(floor_name(f))
	finding := {
		"severity": "error",
		"rule": "floor/name-required",
		"message": sprintf("every platformFloor row must carry a non-empty name: floors are declared by guardrail name (%s)", [registry_file]),
		"path": "$.registry.platformFloor",
	}
}

g_registry_shape contains finding if {
	some f in floors
	not is_positive_integer(floor_version(f))
	finding := {
		"severity": "error",
		"rule": "floor/version-required",
		"message": sprintf("every platformFloor row must carry a floor (a positive integer) (%s)", [registry_file]),
		"path": "$.registry.platformFloor",
	}
}

# --- advisories: the four drifts, named -------------------------------------------

# (1) The escape hatch: a binding that does not ride a rail the
# registry declares. Raw access is a shortcut the platform cannot
# see — the honest platform answer is the rail, not the database
# behind it.
g_escape_hatch contains finding if {
	some b in bindings
	lib.is_nonempty_string(binding_name(b))
	lib.is_nonempty_string(binding_via(b))
	not binding_rides_rail(binding_via(b))
	finding := {
		"severity": "advisory",
		"rule": "binding/escape-hatch",
		"message": sprintf("the data binding '%s' goes around the platform's rails via '%s': an escape hatch is a shortcut the platform cannot see (%s, %s)", [binding_name(b), binding_via(b), manifest_file, registry_file]),
		"path": "$.manifest.dataBindings",
	}
}

# (2) The action outside the rails: the app invokes a platform
# action the spec never granted. Citizen apps run on the spec's
# rails or not at all.
g_action_outside contains finding if {
	some a in actions
	lib.is_nonempty_string(a)
	not spec_grants(a)
	finding := {
		"severity": "advisory",
		"rule": "action/outside-rails",
		"message": sprintf("the app uses the action '%s', a rail the spec never granted: citizen apps run on the spec's rails or not at all (%s, %s)", [a, manifest_file, spec_file]),
		"path": "$.manifest.actions",
	}
}

# (3) The behavior without spec coverage: a component declares
# behavior the spec's coverage never declares. Behavior nobody
# agreed to is the drift that ships.
g_behavior_uncovered contains finding if {
	some c in components
	lib.is_nonempty_string(component_name(c))
	lib.is_nonempty_string(component_behavior(c))
	not spec_covers(component_behavior(c))
	finding := {
		"severity": "advisory",
		"rule": "behavior/uncovered-by-spec",
		"message": sprintf("the component '%s' declares the behavior '%s', which the spec's coverage never declares: behavior without spec coverage is behavior nobody agreed to (%s, %s)", [component_name(c), component_behavior(c), manifest_file, spec_file]),
		"path": "$.manifest.components",
	}
}

# (4) The guardrail below the platform floor: the app builds against
# a guardrail version the registry's floor has passed. Guardrails
# drift after platform upgrades; the floor is the registry's word.
g_guardrail_floors contains finding if {
	some g in guardrails
	lib.is_nonempty_string(guardrail_name(g))
	guardrail_known(guardrail_name(g))
	is_positive_integer(guardrail_version(g))
	floor := floor_for(guardrail_name(g))
	is_positive_integer(floor_version(floor))
	guardrail_version(g) < floor_version(floor)
	finding := {
		"severity": "advisory",
		"rule": "guardrail/below-floor",
		"message": sprintf("the app builds against %s v%v, below the platform floor %v: guardrails drift after platform upgrades, and the floor is the registry's word (%s, %s)", [guardrail_name(g), guardrail_version(g), floor_version(floor), manifest_file, registry_file]),
		"path": "$.manifest.guardrails",
	}
}

# A guardrail the registry never heard of: a promise the platform
# never made, advising the same as a floor miss.
g_guardrail_floors contains finding if {
	some g in guardrails
	lib.is_nonempty_string(guardrail_name(g))
	not guardrail_known(guardrail_name(g))
	finding := {
		"severity": "advisory",
		"rule": "guardrail/unknown",
		"message": sprintf("the app builds against '%s', a guardrail the registry does not know: a guardrail the platform never registered is a promise the platform never made (%s, %s)", [guardrail_name(g), manifest_file, registry_file]),
		"path": "$.manifest.guardrails",
	}
}

# --- the advice cards -----------------------------------------------------------

# The board, in fixed area order: data bindings, actions, spec
# coverage, guardrails — one row per judged item, aligned or
# advises. Only well-formed rows render; a malformed row is a
# finding, not a card.
advice_cards := array.concat(binding_cards, array.concat(action_cards, array.concat(coverage_cards, guardrail_cards)))

# Data bindings: one row per well-formed binding, riding a declared
# rail or going around it.
binding_cards := sort([card |
	some b in bindings
	lib.is_nonempty_string(binding_name(b))
	lib.is_nonempty_string(binding_via(b))
	card := {
		"area": "data bindings",
		"item": binding_name(b),
		"verdict": binding_card_verdict(b),
		"detail": binding_card_detail(b),
	}
])

binding_card_verdict(b) := "advises" if {
	not binding_rides_rail(binding_via(b))
}

binding_card_verdict(b) := "aligned" if {
	binding_rides_rail(binding_via(b))
}

binding_card_detail(b) := sprintf("rides '%s', a rail the registry declares (%s)", [binding_via(b), manifest_file]) if {
	binding_rides_rail(binding_via(b))
}

binding_card_detail(b) := sprintf("goes around the rails via '%s': the platform cannot see this traffic (%s)", [binding_via(b), manifest_file]) if {
	not binding_rides_rail(binding_via(b))
}

# Actions: one row per action used, inside or outside the spec's rails.
action_cards := sort([card |
	some a in actions
	lib.is_nonempty_string(a)
	card := {
		"area": "actions",
		"item": a,
		"verdict": action_card_verdict(a),
		"detail": action_card_detail(a),
	}
])

action_card_verdict(a) := "advises" if {
	not spec_grants(a)
}

action_card_verdict(a) := "aligned" if {
	spec_grants(a)
}

action_card_detail(a) := sprintf("a rail the spec grants (%s)", [spec_file]) if {
	spec_grants(a)
}

action_card_detail(a) := sprintf("outside the spec's rails: the spec never granted this action (%s)", [spec_file]) if {
	not spec_grants(a)
}

# Spec coverage: one row per well-formed component, its behavior
# covered or uncovered.
coverage_cards := sort([card |
	some c in components
	lib.is_nonempty_string(component_name(c))
	lib.is_nonempty_string(component_behavior(c))
	card := {
		"area": "spec coverage",
		"item": component_name(c),
		"verdict": coverage_card_verdict(c),
		"detail": coverage_card_detail(c),
	}
])

coverage_card_verdict(c) := "advises" if {
	not spec_covers(component_behavior(c))
}

coverage_card_verdict(c) := "aligned" if {
	spec_covers(component_behavior(c))
}

coverage_card_detail(c) := sprintf("behavior '%s' is covered by the spec (%s)", [component_behavior(c), spec_file]) if {
	spec_covers(component_behavior(c))
}

coverage_card_detail(c) := sprintf("behavior '%s' is not in the spec's coverage: nobody agreed to it (%s)", [component_behavior(c), spec_file]) if {
	not spec_covers(component_behavior(c))
}

# Guardrails: one row per well-formed guardrail, at or above the
# platform floor, below it, or unknown to the registry. A malformed
# version or a malformed floor row is a finding, not a card.
guardrail_cards := sort([card |
	some g in guardrails
	lib.is_nonempty_string(guardrail_name(g))
	is_positive_integer(guardrail_version(g))
	card := {
		"area": "guardrails",
		"item": guardrail_name(g),
		"verdict": guardrail_card_verdict(g),
		"detail": guardrail_card_detail(g),
	}
])

guardrail_card_verdict(g) := "aligned" if {
	guardrail_meets_floor(g)
}

guardrail_card_verdict(g) := "advises" if {
	not guardrail_meets_floor(g)
}

guardrail_card_detail(g) := sprintf("v%v, at or above the platform floor (%s)", [guardrail_version(g), registry_file]) if {
	guardrail_known(guardrail_name(g))
	guardrail_meets_floor(g)
}

guardrail_card_detail(g) := sprintf("v%v, below the platform floor %v: guardrail drift after the upgrade (%s)", [guardrail_version(g), floor_version(floor_for(guardrail_name(g))), registry_file]) if {
	guardrail_known(guardrail_name(g))
	is_positive_integer(floor_version(floor_for(guardrail_name(g))))
	is_positive_integer(guardrail_version(g))
	guardrail_version(g) < floor_version(floor_for(guardrail_name(g)))
}

guardrail_card_detail(g) := sprintf("the registry does not know this guardrail: a promise the platform never made (%s)", [registry_file]) if {
	not guardrail_known(guardrail_name(g))
}

# --- the verdict ladder -----------------------------------------------------------

# The advisor's ladder, honest about what each rung means: a
# document the advisor cannot read is the only red it can show;
# advisories keep the gate green with the advice on the record; an
# app on its rails with its guardrails at the floor is aligned.
gate_verdict(fs) := "unreadable" if {
	count([f | f := fs[_]; f.severity == "error"]) > 0
}

gate_verdict(fs) := "advises changes" if {
	count([f | f := fs[_]; f.severity == "error"]) == 0
	count([f | f := fs[_]; f.severity == "advisory"]) > 0
}

gate_verdict(fs) := "aligned" if {
	count([f | f := fs[_]; f.severity == "error"]) == 0
	count([f | f := fs[_]; f.severity == "advisory"]) == 0
}

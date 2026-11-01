# The shared model for the citizen spec-rails conformance linter —
# The Software Field Guide, issue #84.
#
# Three documents enter: the CITIZEN APP MANIFEST (the citizen-built
# app as data — its components and the behavior each declares, the
# data bindings it opens and the rails they ride, the platform
# actions it uses, and the guardrails it builds against with their
# versions), the APP SPEC (the rails themselves — the actions the
# spec grants and the behaviors its coverage declares), and the
# PLATFORM GUARDRAIL REGISTRY (the platform's word — the data rails
# a binding may ride and the platform floor each guardrail must
# meet). An app is data until something judges it; the judge models
# a stated subset honestly (binding form, action and coverage
# membership, guardrail versions against the registry floor — not
# the full semantics of any real low-code platform). Every accessor
# here guards its input before touching object fields — a malformed
# document must produce findings, never a WASM trap.
package citizen

import rego.v1

import data.citizen.lib

# --- the input documents ------------------------------------------------------

manifest_doc := v if {
	is_object(input)
	v := object.get(input, "manifest", null)
}

manifest_doc := null if not is_object(input)

spec_doc := v if {
	is_object(input)
	v := object.get(input, "spec", null)
}

spec_doc := null if not is_object(input)

registry_doc := v if {
	is_object(input)
	v := object.get(input, "registry", null)
}

registry_doc := null if not is_object(input)

# The injected clock, guarded: `today` arrives with the input and is
# never read from the wall. Accessed through this accessor so a
# malformed input (an array, a string) can never trap a builtin.
today_date := v if {
	is_object(input)
	v := object.get(input, "today", null)
}

today_date := null if not is_object(input)

# The file names the findings cite, guarded the same way: the CLI and
# the playground inject them so a finding names the document it came
# from. Absent, they degrade to the definite article — a finding still
# says which document offended, just not by file name.
manifest_file := v if {
	is_object(input)
	v := object.get(input, "manifestFile", "the citizen app manifest")
}

manifest_file := "the citizen app manifest" if not is_object(input)

spec_file := v if {
	is_object(input)
	v := object.get(input, "specFile", "the app spec")
}

spec_file := "the app spec" if not is_object(input)

registry_file := v if {
	is_object(input)
	v := object.get(input, "registryFile", "the platform guardrail registry")
}

registry_file := "the platform guardrail registry" if not is_object(input)

# --- arrays, defensively -----------------------------------------------------

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

# A positive integer — versions, guardrail floors are whole numbers.
is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# --- the manifest: the app's components ---------------------------------------

components := [c | some c in as_array(manifest_doc, "components"); is_object(c)]

component_name(c) := object.get(c, "name", null)

component_behavior(c) := object.get(c, "behavior", null)

# --- the manifest: the data bindings -------------------------------------------

bindings := [b | some b in as_array(manifest_doc, "dataBindings"); is_object(b)]

binding_name(b) := object.get(b, "name", null)

binding_mode(b) := object.get(b, "mode", null)

binding_via(b) := object.get(b, "via", null)

# The modeled binding modes: a binding reads or it writes. Anything
# else is a mode the linter never agreed to model.
binding_mode_valid(m) if m in {"read", "write"}

# --- the manifest: the actions used --------------------------------------------

# The platform actions the app invokes, as plain strings — the rail
# names the spec grants or withholds.
actions := [a | some a in as_array(manifest_doc, "actions"); is_string(a)]

# --- the manifest: the guardrails it builds against ------------------------------

guardrails := [g | some g in as_array(manifest_doc, "guardrails"); is_object(g)]

guardrail_name(g) := object.get(g, "name", null)

guardrail_version(g) := object.get(g, "version", null)

# --- the spec: the rails the spec grants ------------------------------------------

# The action rails: the platform actions the spec authorizes. An
# action the manifest uses that the spec never granted is the app
# reaching outside its own rails.
spec_actions := [a | some a in as_array(spec_doc, "actions"); is_string(a)]

spec_grants(name) if {
	some a in spec_actions
	a == name
}

# The behaviors the spec covers: what the spec says the app does. A
# component behavior the spec never covered is behavior nobody
# agreed to.
spec_coverage := [b | some b in as_array(spec_doc, "coverage"); is_string(b)]

spec_covers(behavior) if {
	some b in spec_coverage
	b == behavior
}

# --- the registry: the platform's rails and floors ---------------------------------

# The data rails a binding may ride: the registry declares them, the
# manifest's bindings ride them or go around them.
data_rails := [r | some r in as_array(registry_doc, "dataRails"); is_string(r)]

binding_rides_rail(v) if {
	some r in data_rails
	v == r
}

# The platform floor: the minimum version each guardrail must meet.
# A guardrail below its floor is guardrail drift after a platform
# upgrade — the registry's word, not the app's.
floors := [f | some f in as_array(registry_doc, "platformFloor"); is_object(f)]

floor_name(f) := object.get(f, "name", null)

floor_version(f) := object.get(f, "floor", null)

floor_for(name) := f if {
	some f in floors
	floor_name(f) == name
}

# A manifest guardrail is known to the platform when the registry
# declares a floor for it.
guardrail_known(name) if {
	is_object(floor_for(name))
}

# A guardrail meets the platform floor when its version is at or
# above the floor the registry declares.
guardrail_meets_floor(g) if {
	guardrail_known(guardrail_name(g))
	floor := floor_for(guardrail_name(g))
	is_positive_integer(floor_version(floor))
	is_positive_integer(guardrail_version(g))
	guardrail_version(g) >= floor_version(floor)
}

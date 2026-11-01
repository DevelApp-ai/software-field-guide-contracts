# The shared model for the segment render-consistency gate — The
# Software Field Guide, issue #80.
#
# Four documents enter: the SEGMENT CONTRACT (the microsegmentation
# chapter's YAML — the segments and the rules between them, each rule
# with its direction, type, port, audit-or-enforce mode, and its
# TTL-bound exceptions), the RENDERED POLICIES (one contract rendered
# to N fabrics — every declared fabric's render rows, each citing the
# contract rule it renders), the FLOW EVIDENCE (the flows observed
# during a named audit window), and the PROMOTION REQUEST (the PR
# that moves one audit rule to enforce, citing its flow-evidence
# file). One contract, N fabrics: a rule is not enforced until every
# fabric says so, and promotion is evidence, not assertion. Every
# accessor here guards its input before touching object fields — a
# malformed document must produce findings, never a WASM trap.
package segment

import rego.v1

import data.segment.lib

# --- the input documents ------------------------------------------------------

contract_doc := v if {
	is_object(input)
	v := object.get(input, "contract", null)
}

contract_doc := null if not is_object(input)

renders_doc := v if {
	is_object(input)
	v := object.get(input, "renders", null)
}

renders_doc := null if not is_object(input)

flows_doc := v if {
	is_object(input)
	v := object.get(input, "flows", null)
}

flows_doc := null if not is_object(input)

promotion_doc := v if {
	is_object(input)
	v := object.get(input, "promotion", null)
}

promotion_doc := null if not is_object(input)

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
contract_file := v if {
	is_object(input)
	v := object.get(input, "contractFile", "the segment contract")
}

contract_file := "the segment contract" if not is_object(input)

renders_file := v if {
	is_object(input)
	v := object.get(input, "rendersFile", "the fabric renders")
}

renders_file := "the fabric renders" if not is_object(input)

flows_file := v if {
	is_object(input)
	v := object.get(input, "flowsFile", "the flow evidence")
}

flows_file := "the flow evidence" if not is_object(input)

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

# --- the segment contract: the segments ---------------------------------------

segments := [s | some s in as_array(contract_doc, "segments"); is_string(s)]

segment_named(name) if {
	some s in segments
	s == name
}

# --- the segment contract: the rules ------------------------------------------

rules := [r | some r in as_array(contract_doc, "rules"); is_object(r)]

rule_id(r) := object.get(r, "id", null)

rule_from(r) := object.get(r, "from", null)

rule_to(r) := object.get(r, "to", null)

rule_type(r) := object.get(r, "type", null)

rule_port(r) := object.get(r, "port", null)

rule_direction(r) := object.get(r, "direction", null)

rule_mode(r) := object.get(r, "mode", null)

# The modeled subset, honest by design: the gate verifies direction,
# type, and port within the fields it models — not full eBPF or CIL
# semantics, and the findings say so.
modeled_types := {"tcp", "udp"}

modeled_directions := {"ingress", "egress"}

modeled_modes := {"audit", "enforce"}

is_valid_port(v) if {
	is_number(v)
	v == floor(v)
	v >= 1
	v <= 65535
}

is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# A rule a lookup can trust: named, its segments named, and its
# direction, type, port, and mode inside the modeled subset. Shape
# quality beyond this is the validator's finding, never an ambiguity
# for lookups.
rule_row_well_formed(r) if {
	is_object(r)
	lib.is_nonempty_string(rule_id(r))
	lib.is_nonempty_string(rule_from(r))
	lib.is_nonempty_string(rule_to(r))
	rule_type(r) in modeled_types
	is_valid_port(rule_port(r))
	rule_direction(r) in modeled_directions
	rule_mode(r) in modeled_modes
}

# The well-formed contract rules, in document order.
well_formed_rules := [r | some r in rules; rule_row_well_formed(r)]

# The position of a rule in the contract document, so a finding can
# cite the exact row.
rule_index(id) := i if {
	matches := [i |
		some i, r in rules
		rule_row_well_formed(r)
		object.get(r, "id", null) == id
	]
	count(matches) > 0
	i := matches[0]
}

# The first well-formed contract rule with this id, in document order —
# the rule the joins judge, deterministically. A duplicate id is the
# validator's finding, never an ambiguity here.
rule_named(id) := r if {
	matches := [r |
		some r in well_formed_rules
		rule_id(r) == id
	]
	count(matches) > 0
	r := matches[0]
}

rule_declared(id) if {
	some r in well_formed_rules
	rule_id(r) == id
}

# --- the segment contract: the TTL-bound exceptions -----------------------------

# Exceptions are TTL-bound by design: an exception without its expiry
# date is a rule state that never ends, and the contract lies about
# when it stops.
exception_rows(r) := [e | some e in as_array(r, "exceptions"); is_object(e)]

exception_reason(e) := object.get(e, "reason", null)

exception_expires_on(e) := object.get(e, "expiresOn", null)

exception_row_well_formed(e) if {
	is_object(e)
	lib.is_nonempty_string(exception_reason(e))
	lib.is_valid_date(exception_expires_on(e))
}

# --- the rendered policies: fabrics and rows -------------------------------------

fabric_names := [f | some f in as_array(renders_doc, "fabrics"); is_string(f)]

# The declared fabrics, sorted — the N in "one contract, N fabrics".
# Every well-formed contract rule must be rendered on every one of
# them; the join iterates this list, not the rows.
declared_fabrics := sort({f |
	some f in fabric_names
	lib.is_nonempty_string(f)
})

fabric_declared(fabric) if {
	some f in declared_fabrics
	f == fabric
}

render_rows := [x | some x in as_array(renders_doc, "rules"); is_object(x)]

render_fabric(x) := object.get(x, "fabric", null)

render_rule(x) := object.get(x, "rule", null)

render_direction(x) := object.get(x, "direction", null)

render_type(x) := object.get(x, "type", null)

render_port(x) := object.get(x, "port", null)

# A render row a join can trust: its fabric and its contract rule
# named, and its direction, type, and port inside the modeled subset.
render_row_well_formed(x) if {
	is_object(x)
	lib.is_nonempty_string(render_fabric(x))
	lib.is_nonempty_string(render_rule(x))
	render_direction(x) in modeled_directions
	render_type(x) in modeled_types
	is_valid_port(render_port(x))
}

# The well-formed render rows citing one contract rule on one fabric,
# in document order.
render_rows_for(id, fabric) := [x |
	some x in render_rows
	render_row_well_formed(x)
	render_rule(x) == id
	render_fabric(x) == fabric
]

fabric_has_rule(fabric, r) if {
	count(render_rows_for(rule_id(r), fabric)) > 0
}

# --- the flow evidence: the window and the flows ---------------------------------

flow_window_from := v if {
	is_object(flows_doc)
	w := object.get(flows_doc, "window", null)
	is_object(w)
	v := object.get(w, "from", null)
}

flow_window_from := null if {
	not is_object(flows_doc)
}

flow_window_from := null if {
	is_object(flows_doc)
	not is_object(object.get(flows_doc, "window", null))
}

flow_window_to := v if {
	is_object(flows_doc)
	w := object.get(flows_doc, "window", null)
	is_object(w)
	v := object.get(w, "to", null)
}

flow_window_to := null if {
	not is_object(flows_doc)
}

flow_window_to := null if {
	is_object(flows_doc)
	not is_object(object.get(flows_doc, "window", null))
}

flows_judged if {
	is_object(flows_doc)
	lib.is_valid_date(flow_window_from)
	lib.is_valid_date(flow_window_to)
	lib.date_to_days(flow_window_from) <= lib.date_to_days(flow_window_to)
}

flow_rows := [f | some f in as_array(flows_doc, "flows"); is_object(f)]

flow_from(f) := object.get(f, "from", null)

flow_to(f) := object.get(f, "to", null)

flow_type(f) := object.get(f, "type", null)

flow_port(f) := object.get(f, "port", null)

flow_count(f) := object.get(f, "count", null)

# An observed flow the joins can trust: both segments and the type
# named, a real port, and a positive integer count.
flow_row_well_formed(f) if {
	is_object(f)
	lib.is_nonempty_string(flow_from(f))
	lib.is_nonempty_string(flow_to(f))
	flow_type(f) in modeled_types
	is_valid_port(flow_port(f))
	is_positive_integer(flow_count(f))
}

# The matched-flow count for one well-formed contract rule: the sum
# of the observed flows whose from, to, type, and port equal the
# rule's — the evidence the dead-rule review and the promotion gate
# read. An empty sum is zero: a rule nothing exercised.
matched_flow_count(r) := sum([flow_count(f) |
	some f in flow_rows
	flow_row_well_formed(f)
	flow_from(f) == rule_from(r)
	flow_to(f) == rule_to(r)
	flow_type(f) == rule_type(r)
	flow_port(f) == rule_port(r)
])

# --- the promotion request: the PR and its citations -------------------------------

promotion_present if is_object(promotion_doc)

promo_pr := v if {
	is_object(promotion_doc)
	v := object.get(promotion_doc, "pr", null)
}

promo_pr := null if not is_object(promotion_doc)

promo_rule := v if {
	is_object(promotion_doc)
	v := object.get(promotion_doc, "rule", null)
}

promo_rule := null if not is_object(promotion_doc)

promo_target := v if {
	is_object(promotion_doc)
	v := object.get(promotion_doc, "to", null)
}

promo_target := null if not is_object(promotion_doc)

promo_evidence_file := v if {
	is_object(promotion_doc)
	v := object.get(promotion_doc, "evidenceFile", null)
}

promo_evidence_file := null if not is_object(promotion_doc)

promo_window_from := v if {
	is_object(promotion_doc)
	w := object.get(promotion_doc, "window", null)
	is_object(w)
	v := object.get(w, "from", null)
}

promo_window_from := null if not is_object(promotion_doc)

promo_window_from := null if {
	is_object(promotion_doc)
	not is_object(object.get(promotion_doc, "window", null))
}

promo_window_to := v if {
	is_object(promotion_doc)
	w := object.get(promotion_doc, "window", null)
	is_object(w)
	v := object.get(w, "to", null)
}

promo_window_to := null if not is_object(promotion_doc)

promo_window_to := null if {
	is_object(promotion_doc)
	not is_object(object.get(promotion_doc, "window", null))
}

# The promotion window, judged: both dates real, in order.
promotion_window_valid if {
	lib.is_valid_date(promo_window_from)
	lib.is_valid_date(promo_window_to)
	lib.date_to_days(promo_window_from) <= lib.date_to_days(promo_window_to)
}

# The promotion window falls inside the evidence window — the PR may
# only claim flows its cited evidence actually covers.
promotion_window_within_evidence if {
	flows_judged
	promotion_window_valid
	lib.date_to_days(promo_window_from) >= lib.date_to_days(flow_window_from)
	lib.date_to_days(promo_window_to) <= lib.date_to_days(flow_window_to)
}

# The evidence is in hand: the PR names its evidence file and the flow
# document was given to the gate.
promotion_evidence_in_hand if {
	lib.is_nonempty_string(promo_evidence_file)
	is_object(flows_doc)
}

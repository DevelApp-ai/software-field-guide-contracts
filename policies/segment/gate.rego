# Segment render-consistency and flow-evidence gate — The Software
# Field Guide, issue #80.
#
# One segment contract rendered to N fabrics: every rule declared in
# the contract must be present in every declared render (missing-in-
# render), no render may carry a rule the contract never had
# (not-in-contract), and the rendered direction, type, and port must
# agree with the contract within the modeled subset — the gate is
# honest about what it models, not pretending to full eBPF or CIL
# semantics. Promotion from audit to enforce is a PR citing a
# flow-evidence file: without the cited evidence the promotion fails
# (promotion is evidence, not assertion), and the evidence must show
# matched flows inside the PR's window. A rule nothing exercises
# across the evidence window is a review flag — dead rules accumulate
# forever unless something flags them. The rule cards render the
# decision: one row per contract rule, consistent, audit, missing,
# mismatched, or dead.
#
# Input (JSON): {"contract": {...}, "renders": {...}, "flows": {...},
#                "promotion": {...}, "today": "YYYY-MM-DD",
#                "contractFile": "...", "rendersFile": "...", "flowsFile": "..."}
# Result:       {"valid": bool, "findings": [...], "rules": [...], "verdict": "..."}
package segment

import rego.v1

import data.segment.lib

# --- entrypoint -------------------------------------------------------------

gate := result if {
	fs := sort([f | some f in gate_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
		"rules": rule_cards,
		"verdict": gate_verdict(fs),
	}
}

gate_findings := ((((((((((((((((((((f_input_invalid | f_today_invalid) | f_contract_missing) | f_renders_missing) | f_renders_stamps) | f_fabrics_array) | f_fabrics_content) | f_render_array) | f_render_content) | f_render_refs) | f_render_missing) | f_render_dupes) | f_direction_mismatch) | f_type_mismatch) | f_port_mismatch) | f_flows_array) | f_flow_content) | f_flow_window) | f_dead_rules) | f_promotion_shape) | f_promotion_refs) | f_promotion_evidence

# --- findings: the renders document is missing, unread, or stale -----------------

f_renders_missing contains finding if {
	is_object(input)
	not is_object(renders_doc)
	finding := {
		"severity": "error",
		"rule": "renders/missing",
		"message": "the rendered policies are required: pass them as input.renders — one contract, N fabrics, and the renders are how the N answer",
		"path": "$.renders",
	}
}

# The renders are an owned, versioned artifact: rendered policies that
# nobody re-read are rendered policies nobody still believes.
f_renders_stamps contains finding if {
	is_object(renders_doc)
	not is_positive_integer(object.get(renders_doc, "version", null))
	finding := {
		"severity": "error",
		"rule": "renders/version-required",
		"message": "the rendered policies must carry a version (a positive integer): the renders are versioned like the contract they render",
		"path": "$.renders.version",
	}
}

f_renders_stamps contains finding if {
	is_object(renders_doc)
	not lib.is_valid_date(object.get(renders_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "renders/reviewed-on-invalid",
		"message": "the rendered policies must carry reviewedOn as a real YYYY-MM-DD date",
		"path": "$.renders.reviewedOn",
	}
}

f_renders_stamps contains finding if {
	is_object(renders_doc)
	lib.is_valid_date(object.get(renders_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(object.get(renders_doc, "reviewedOn", null)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "renders/reviewed-in-future",
		"message": "the rendered policies carry a reviewedOn date in the future",
		"path": "$.renders.reviewedOn",
	}
}

f_renders_stamps contains finding if {
	is_object(renders_doc)
	lib.is_valid_date(object.get(renders_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(renders_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "renders/reviewed-stale",
		"message": "the rendered policies were reviewed more than 365 days before today: these renders are stale — a fabric rendering a year-old contract enforces a year-old estate",
		"path": "$.renders.reviewedOn",
	}
}

# --- findings: the declared fabrics -----------------------------------------------

f_fabrics_array contains finding if {
	is_object(renders_doc)
	not is_array(object.get(renders_doc, "fabrics", null))
	finding := {
		"severity": "error",
		"rule": "fabrics/must-be-array",
		"message": "fabrics must be an array of the fabric names the renders cover",
		"path": "$.renders.fabrics",
	}
}

f_fabrics_array contains finding if {
	is_object(renders_doc)
	is_array(object.get(renders_doc, "fabrics", null))
	count(declared_fabrics) == 0
	finding := {
		"severity": "error",
		"rule": "fabrics/required",
		"message": "the rendered policies must declare at least one fabric: one contract with no fabrics to render it is a contract enforced nowhere",
		"path": "$.renders.fabrics",
	}
}

f_fabrics_content contains finding if {
	some i, f in as_array(renders_doc, "fabrics")
	not lib.is_nonempty_string(f)
	finding := {
		"severity": "error",
		"rule": "fabric/name-required",
		"message": sprintf("fabric entry %d must carry a non-empty name: an unnamed fabric cannot be cited in a finding", [i]),
		"path": sprintf("$.renders.fabrics[%d]", [i]),
	}
}

f_fabrics_content contains finding if {
	some name in fabric_names
	lib.is_nonempty_string(name)
	count([f | some f in fabric_names; f == name]) > 1
	finding := {
		"severity": "error",
		"rule": "fabric/name-duplicate",
		"message": sprintf("fabric '%s' is declared more than once: a fabric declared twice is a render the gate cannot count", [name]),
		"path": "$.renders.fabrics",
	}
}

# --- findings: the render rows ------------------------------------------------------

f_render_array contains finding if {
	is_object(renders_doc)
	not is_array(object.get(renders_doc, "rules", null))
	finding := {
		"severity": "error",
		"rule": "renders/rules-must-be-array",
		"message": "the render rows must be an array of {fabric, rule, direction, type, port} rows",
		"path": "$.renders.rules",
	}
}

f_render_array contains finding if {
	is_object(renders_doc)
	is_array(object.get(renders_doc, "rules", null))
	count(render_rows) == 0
	finding := {
		"severity": "error",
		"rule": "renders/rules-required",
		"message": "the rendered policies must carry at least one render row: renders with no rows render nothing",
		"path": "$.renders.rules",
	}
}

f_render_content contains finding if {
	some i, x in as_array(renders_doc, "rules")
	not is_object(x)
	finding := {
		"severity": "error",
		"rule": "renders/row-must-be-object",
		"message": sprintf("render row %d must be an object with fabric, rule, direction, type, and port", [i]),
		"path": sprintf("$.renders.rules[%d]", [i]),
	}
}

f_render_content contains finding if {
	some i, x in render_rows
	not render_row_well_formed(x)
	finding := {
		"severity": "error",
		"rule": "render/row-invalid",
		"message": sprintf("render row %d must carry fabric and rule (non-empty strings) and direction, type, and port inside the modeled subset (ingress or egress, tcp or udp, a port from 1 to 65535)", [i]),
		"path": sprintf("$.renders.rules[%d]", [i]),
	}
}

# --- findings: the render joins — the issue's core rule ------------------------------

# A render row on a fabric the document never declared: the join can
# only count fabrics the renders declare.
f_render_refs contains finding if {
	some i, x in render_rows
	render_row_well_formed(x)
	not fabric_declared(render_fabric(x))
	finding := {
		"severity": "error",
		"rule": "render/fabric-undeclared",
		"message": sprintf("a render row cites rule '%s' on fabric '%s', which the renders never declared in fabrics: either the row is on a fabric nobody owns, or the fabric list forgot a fabric — the two disagree", [render_rule(x), render_fabric(x)]),
		"path": sprintf("$.renders.rules[%d].fabric", [i]),
	}
}

# A render carrying a rule the contract never had — the mirror image
# of the missing render, and just as silent without the gate.
f_render_refs contains finding if {
	some i, x in render_rows
	render_row_well_formed(x)
	fabric_declared(render_fabric(x))
	not rule_declared(render_rule(x))
	finding := {
		"severity": "error",
		"rule": "render/rule-unknown",
		"message": sprintf("the '%s' fabric render (%s) carries rule '%s', which the segment contract (%s) never declared: a render carrying a rule the contract never had drifts silently — one contract, N fabrics, and the fabric is rendering somebody else's", [render_fabric(x), renders_file, render_rule(x), contract_file]),
		"path": sprintf("$.renders.rules[%d].rule", [i]),
	}
}

# A rule added to the contract but missing from one render — the
# issue's own first failure mode, cited on both documents.
f_render_missing contains finding if {
	some r in well_formed_rules
	some fabric in declared_fabrics
	not fabric_has_rule(fabric, r)
	finding := {
		"severity": "error",
		"rule": "render/rule-missing",
		"message": sprintf("rule '%s' (%s → %s, %s/%d, %s) is declared in the segment contract (%s) but the '%s' fabric render (%s) never rendered it: a rule added to the contract but missing from one render drifts silently — a rule is not enforced until every fabric says so", [rule_id(r), rule_from(r), rule_to(r), rule_type(r), rule_port(r), rule_direction(r), contract_file, fabric, renders_file]),
		"path": sprintf("$.contract.rules[%d]", [rule_index(rule_id(r))]),
	}
}

# The same rule rendered twice on one fabric: a render the gate
# cannot count is a render that hides the missing one.
f_render_dupes contains finding if {
	some id in render_rule_ids
	some fabric in declared_fabrics
	count(render_rows_for(id, fabric)) > 1
	finding := {
		"severity": "error",
		"rule": "render/rule-duplicate",
		"message": sprintf("rule '%s' is rendered %d times on fabric '%s': two render rows for one rule is a render nobody can diff", [id, count(render_rows_for(id, fabric)), fabric]),
		"path": "$.renders.rules",
	}
}

render_rule_ids := sort({render_rule(x) |
	some x in render_rows
	render_row_well_formed(x)
})

# --- findings: the modeled-subset mismatches -----------------------------------------

# Direction, type, and port — the fields the gate models, compared
# one row at a time. The honesty is in the naming: the findings say
# which field disagrees, on which fabric, citing both documents.
f_direction_mismatch contains finding if {
	some i, x in render_rows
	render_row_well_formed(x)
	fabric_declared(render_fabric(x))
	r := rule_named(render_rule(x))
	render_direction(x) != rule_direction(r)
	finding := {
		"severity": "error",
		"rule": "render/direction-mismatch",
		"message": sprintf("rule '%s' is %s in the segment contract (%s) but the '%s' fabric rendered it %s (%s): the two documents disagree about which way the traffic flows", [render_rule(x), rule_direction(r), contract_file, render_fabric(x), render_direction(x), renders_file]),
		"path": sprintf("$.renders.rules[%d].direction", [i]),
	}
}

f_type_mismatch contains finding if {
	some i, x in render_rows
	render_row_well_formed(x)
	fabric_declared(render_fabric(x))
	r := rule_named(render_rule(x))
	render_type(x) != rule_type(r)
	finding := {
		"severity": "error",
		"rule": "render/type-mismatch",
		"message": sprintf("rule '%s' carries type %s in the segment contract (%s) but the '%s' fabric rendered it %s (%s): the modeled subset disagrees — the two documents are not rendering the same protocol", [render_rule(x), rule_type(r), contract_file, render_fabric(x), render_type(x), renders_file]),
		"path": sprintf("$.renders.rules[%d].type", [i]),
	}
}

f_port_mismatch contains finding if {
	some i, x in render_rows
	render_row_well_formed(x)
	fabric_declared(render_fabric(x))
	r := rule_named(render_rule(x))
	render_port(x) != rule_port(r)
	finding := {
		"severity": "error",
		"rule": "render/port-mismatch",
		"message": sprintf("rule '%s' carries port %d in the segment contract (%s) but the '%s' fabric rendered it %d (%s): the two documents disagree about which port the traffic enters", [render_rule(x), rule_port(r), contract_file, render_fabric(x), render_port(x), renders_file]),
		"path": sprintf("$.renders.rules[%d].port", [i]),
	}
}

# --- findings: the flow evidence window ----------------------------------------------

f_flows_array contains finding if {
	is_object(flows_doc)
	not is_object(object.get(flows_doc, "window", null))
	finding := {
		"severity": "error",
		"rule": "flows/window-required",
		"message": "the flow evidence must carry its window: observed flows without the window that observed them are evidence about no time at all",
		"path": "$.flows.window",
	}
}

f_flow_window contains finding if {
	is_object(flows_doc)
	w := object.get(flows_doc, "window", null)
	is_object(w)
	not lib.is_valid_date(object.get(w, "from", null))
	finding := {
		"severity": "error",
		"rule": "flows/window-invalid",
		"message": "the flow evidence window must carry from as a real YYYY-MM-DD date",
		"path": "$.flows.window.from",
	}
}

f_flow_window contains finding if {
	is_object(flows_doc)
	w := object.get(flows_doc, "window", null)
	is_object(w)
	not lib.is_valid_date(object.get(w, "to", null))
	finding := {
		"severity": "error",
		"rule": "flows/window-invalid",
		"message": "the flow evidence window must carry to as a real YYYY-MM-DD date",
		"path": "$.flows.window.to",
	}
}

f_flow_window contains finding if {
	is_object(flows_doc)
	lib.is_valid_date(flow_window_from)
	lib.is_valid_date(flow_window_to)
	lib.date_to_days(flow_window_from) > lib.date_to_days(flow_window_to)
	finding := {
		"severity": "error",
		"rule": "flows/window-invalid",
		"message": sprintf("the flow evidence window runs from %s to %s, which is backwards: a window that ends before it starts observed nothing", [flow_window_from, flow_window_to]),
		"path": "$.flows.window",
	}
}

# Evidence cannot cover the future: a window ending after today claims
# to have observed flows that have not happened.
f_flow_window contains finding if {
	is_object(flows_doc)
	lib.is_valid_date(flow_window_to)
	lib.is_valid_date(today_date)
	lib.date_to_days(flow_window_to) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "flows/window-in-future",
		"message": sprintf("the flow evidence window ends on %s, which is in the future: evidence cannot arrive before the flows it evidences", [flow_window_to]),
		"path": "$.flows.window.to",
	}
}

f_flow_window contains finding if {
	is_object(flows_doc)
	not lib.is_valid_date(object.get(flows_doc, "reviewedOn", null))
	finding := {
		"severity": "error",
		"rule": "flows/reviewed-on-invalid",
		"message": "the flow evidence must carry reviewedOn as a real YYYY-MM-DD date: evidence has a shelf life",
		"path": "$.flows.reviewedOn",
	}
}

f_flow_window contains finding if {
	is_object(flows_doc)
	lib.is_valid_date(object.get(flows_doc, "reviewedOn", null))
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(object.get(flows_doc, "reviewedOn", null)) > 365
	finding := {
		"severity": "error",
		"rule": "flows/reviewed-stale",
		"message": "the flow evidence was reviewed more than 365 days before today: stale flow evidence says nothing about the estate rendering today",
		"path": "$.flows.reviewedOn",
	}
}

f_flow_content contains finding if {
	is_object(flows_doc)
	not is_array(object.get(flows_doc, "flows", null))
	finding := {
		"severity": "error",
		"rule": "flows/must-be-array",
		"message": "flows must be an array of {from, to, type, port, count} observations",
		"path": "$.flows.flows",
	}
}

f_flow_content contains finding if {
	some i, f in as_array(flows_doc, "flows")
	not is_object(f)
	finding := {
		"severity": "error",
		"rule": "flows/row-must-be-object",
		"message": sprintf("flow entry %d must be an object with from, to, type, port, and count", [i]),
		"path": sprintf("$.flows.flows[%d]", [i]),
	}
}

f_flow_content contains finding if {
	some i, f in flow_rows
	not flow_row_well_formed(f)
	finding := {
		"severity": "error",
		"rule": "flow/row-invalid",
		"message": sprintf("flow entry %d must carry from and to (non-empty strings), type and port inside the modeled subset (tcp or udp, a port from 1 to 65535), and a positive integer count", [i]),
		"path": sprintf("$.flows.flows[%d]", [i]),
	}
}

# --- findings: the dead-rule review flag ----------------------------------------------

# A rule nothing exercises across the evidence window: dead rules
# accumulate forever without a flag — this is the review, not the
# verdict; the rule stays valid while the review happens.
f_dead_rules contains finding if {
	some r in well_formed_rules
	flows_judged
	matched_flow_count(r) == 0
	finding := {
		"severity": "warning",
		"rule": "flows/dead-rule",
		"message": sprintf("rule '%s' (%s → %s, %s/%d, %s) matched zero flows across the evidence window %s..%s (%s): a rule nothing exercises is a rule nobody wants — review it or remove it", [rule_id(r), rule_from(r), rule_to(r), rule_type(r), rule_port(r), rule_direction(r), flow_window_from, flow_window_to, flows_file]),
		"path": sprintf("$.contract.rules[%d]", [rule_index(rule_id(r))]),
	}
}

# --- findings: the promotion request ---------------------------------------------------

# The promotion is a PR: it names the change and the rule it moves.
# Without its PR the promotion is a whisper.
f_promotion_shape contains finding if {
	promotion_present
	not lib.is_nonempty_string(promo_pr)
	finding := {
		"severity": "error",
		"rule": "promotion/pr-required",
		"message": "the promotion request must name its PR: audit→enforce promotion is a PR citing evidence, not a suggestion",
		"path": "$.promotion.pr",
	}
}

f_promotion_shape contains finding if {
	promotion_present
	not lib.is_nonempty_string(promo_rule)
	finding := {
		"severity": "error",
		"rule": "promotion/rule-required",
		"message": "the promotion request must name the rule it promotes",
		"path": "$.promotion.rule",
	}
}

f_promotion_shape contains finding if {
	promotion_present
	promo_target != "enforce"
	finding := {
		"severity": "error",
		"rule": "promotion/target-invalid",
		"message": sprintf("the promotion request must target enforce (got %s): audit→enforce is the only promotion this gate models, and it says so", [promo_target]),
		"path": "$.promotion.to",
	}
}

f_promotion_shape contains finding if {
	promotion_present
	not promotion_window_valid
	finding := {
		"severity": "error",
		"rule": "promotion/window-invalid",
		"message": "the promotion request must carry a window with real from and to dates in order: the PR claims traffic in a window it must name",
		"path": "$.promotion.window",
	}
}

# The rule the PR promotes must exist, and must be in audit mode —
# promoting a rule that is already enforced is a PR about nothing.
f_promotion_refs contains finding if {
	promotion_present
	lib.is_nonempty_string(promo_rule)
	not rule_declared(promo_rule)
	finding := {
		"severity": "error",
		"rule": "promotion/rule-unknown",
		"message": sprintf("the promotion request names rule '%s', which the segment contract (%s) never declared: the PR is about a rule nobody owns", [promo_rule, contract_file]),
		"path": "$.promotion.rule",
	}
}

f_promotion_refs contains finding if {
	promotion_present
	r := rule_named(promo_rule)
	rule_mode(r) != "audit"
	finding := {
		"severity": "error",
		"rule": "promotion/rule-not-audit",
		"message": sprintf("the promotion request names rule '%s', which is already in %s mode: only a rule in audit can be promoted to enforce", [promo_rule, rule_mode(r)]),
		"path": "$.promotion.rule",
	}
}

# --- findings: the promotion's evidence — the issue's second core rule -----------------

# Promotion is evidence, not assertion: the PR must cite its
# flow-evidence file, and the gate must hold the evidence it cites.
f_promotion_evidence contains finding if {
	promotion_present
	lib.is_nonempty_string(promo_rule)
	rule_declared(promo_rule)
	not lib.is_nonempty_string(promo_evidence_file)
	finding := {
		"severity": "error",
		"rule": "promotion/no-flow-evidence",
		"message": sprintf("the promotion of rule '%s' to enforce cites no flow-evidence file: promotion is evidence, not assertion — the PR must name the window's observed flows", [promo_rule]),
		"path": "$.promotion.evidenceFile",
	}
}

f_promotion_evidence contains finding if {
	promotion_present
	lib.is_nonempty_string(promo_rule)
	rule_declared(promo_rule)
	lib.is_nonempty_string(promo_evidence_file)
	not is_object(flows_doc)
	finding := {
		"severity": "error",
		"rule": "promotion/no-flow-evidence",
		"message": sprintf("the promotion of rule '%s' to enforce cites %s, but the gate was not given that flow evidence: a PR citing evidence nobody can read is an assertion wearing evidence's clothes", [promo_rule, promo_evidence_file]),
		"path": "$.promotion.evidenceFile",
	}
}

# The evidence in hand must show the traffic: a promotion whose
# evidence shows zero matched flows promises traffic the window never
# saw.
f_promotion_evidence contains finding if {
	promotion_present
	promotion_evidence_in_hand
	r := rule_named(promo_rule)
	flows_judged
	matched_flow_count(r) == 0
	finding := {
		"severity": "error",
		"rule": "promotion/no-matched-flows",
		"message": sprintf("the promotion of rule '%s' to enforce cites %s, but the evidence shows zero matched flows for the rule: the PR promises traffic the window never saw", [promo_rule, promo_evidence_file]),
		"path": "$.promotion.evidenceFile",
	}
}

# The PR may only claim flows its cited evidence covers: a promotion
# window outside the evidence window is a claim about unobserved
# traffic.
f_promotion_evidence contains finding if {
	promotion_present
	promotion_evidence_in_hand
	flows_judged
	promotion_window_valid
	not promotion_window_within_evidence
	finding := {
		"severity": "error",
		"rule": "promotion/window-outside-evidence",
		"message": sprintf("the promotion of rule '%s' to enforce claims the window %s..%s, but the cited evidence (%s) covers %s..%s: the PR may only claim flows its evidence actually observed", [promo_rule, promo_window_from, promo_window_to, promo_evidence_file, flow_window_from, flow_window_to]),
		"path": "$.promotion.window",
	}
}

# --- rule cards: the verdict the playground renders --------------------------------

# One card per well-formed contract rule, sorted by rule id:
# consistent (rendered everywhere, exercised), audit (awaiting or
# carrying its promotion evidence), missing (a fabric never rendered
# it), mismatched (a fabric disagrees), or dead (zero matched flows).
rule_cards := [card |
	id := sort({rule_id(r) |
		some r in well_formed_rules
	})[_]
	r := rule_named(id)
	card := {
		"rule": id,
		"mode": rule_mode(r),
		"verdict": rule_verdict(r),
		"detail": rule_detail(r),
	}
]

rule_verdict(r) := "missing" if {
	count(missing_fabrics(r)) > 0
}

rule_verdict(r) := "mismatched" if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) > 0
}

rule_verdict(r) := "dead" if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) == 0
	flows_judged
	matched_flow_count(r) == 0
}

rule_verdict(r) := "audit" if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) == 0
	rule_mode(r) == "audit"
	not rule_dead(r)
}

rule_verdict(r) := "consistent" if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) == 0
	not flows_judged
	rule_mode(r) == "enforce"
}

rule_verdict(r) := "consistent" if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) == 0
	flows_judged
	matched_flow_count(r) > 0
	rule_mode(r) == "enforce"
}

# The fabrics that never rendered the rule, in declared order.
missing_fabrics(r) := [f |
	some f in declared_fabrics
	not fabric_has_rule(f, r)
]

# The fields the rendered rows disagree on, with the fabric that
# disagrees — in document order, first disagreement wins the detail.
mismatched_fields(r) := [{"field": field, "fabric": render_fabric(x)} |
	some x in render_rows_for(rule_id(r), declared_fabrics[_])
	field := disagreeing_field(x, r)
]

disagreeing_field(x, r) := "direction" if {
	render_direction(x) != rule_direction(r)
}

disagreeing_field(x, r) := "type" if {
	render_direction(x) == rule_direction(r)
	render_type(x) != rule_type(r)
}

disagreeing_field(x, r) := "port" if {
	render_direction(x) == rule_direction(r)
	render_type(x) == rule_type(r)
	render_port(x) != rule_port(r)
}

rule_detail(r) := sprintf("not rendered on %s", [concat(", ", missing_fabrics(r))]) if {
	count(missing_fabrics(r)) > 0
}

rule_detail(r) := sprintf("%s disagrees on %s (%s)", [mismatched_fields(r)[0].fabric, mismatched_fields(r)[0].field, renders_file]) if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) > 0
}

rule_detail(r) := sprintf("zero matched flows across the window %s..%s (%s)", [flow_window_from, flow_window_to, flows_file]) if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) == 0
	flows_judged
	matched_flow_count(r) == 0
}

rule_detail(r) := sprintf("rendered on %s; no flow evidence judged", [concat(", ", declared_fabrics)]) if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) == 0
	not flows_judged
	rule_mode(r) == "enforce"
}

rule_detail(r) := sprintf("rendered on %s; %d matched flows across the window", [concat(", ", declared_fabrics), matched_flow_count(r)]) if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) == 0
	flows_judged
	matched_flow_count(r) > 0
	rule_mode(r) == "enforce"
}

rule_detail(r) := audit_detail(r) if {
	count(missing_fabrics(r)) == 0
	count(mismatched_fields(r)) == 0
	rule_mode(r) == "audit"
	not rule_dead(r)
}

audit_detail(r) := sprintf("promotion %s to enforce cites %s — %d matched flows in the window", [promo_pr, promo_evidence_file, matched_flow_count(r)]) if {
	promotion_promotes(rule_id(r))
	promotion_evidence_in_hand
	flows_judged
}

audit_detail(r) := "awaiting a promotion PR with flow evidence" if {
	not promotion_promotes(rule_id(r))
}

audit_detail(r) := "promotion cites evidence not yet in hand" if {
	promotion_promotes(rule_id(r))
	not promotion_evidence_in_hand
}

audit_detail(r) := "promotion cites evidence the gate cannot judge — the evidence window is invalid" if {
	promotion_promotes(rule_id(r))
	promotion_evidence_in_hand
	not flows_judged
}

rule_dead(r) if {
	flows_judged
	matched_flow_count(r) == 0
}

promotion_promotes(id) if {
	promotion_present
	promo_rule == id
}

# --- the gate verdict ------------------------------------------------------------

gate_verdict(fs) := "inconsistent" if {
	count([f | f := fs[_]; f.severity == "error"]) > 0
}

gate_verdict(fs) := "review" if {
	count([f | f := fs[_]; f.severity == "error"]) == 0
	count([f | f := fs[_]; f.severity == "warning"]) > 0
}

gate_verdict(fs) := "consistent" if {
	count([f | f := fs[_]; f.severity == "error"]) == 0
	count([f | f := fs[_]; f.severity == "warning"]) == 0
}

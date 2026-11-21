# The shared model for the data contract conformance validator —
# The Software Field Guide, issue #106.
#
# Two documents enter: the DATA CONTRACT (the dataset's promises as
# data — the schema it is bound to, the freshness SLA its consumers
# may rely on, the quality thresholds it must not fall below, the
# owner who answers for it, the consumers who rely on it, the named
# checks that enforce it in CI, and the change methodology that
# governs its evolution) and the ENFORCEMENT RECORD (the CI's word —
# the checks it actually ran, for one dataset, and the day each ran).
# The validator models a stated subset honestly: it checks the
# contract's own completeness — every clause present, internally
# consistent, and datable — not that enforcement actually ran while
# CI was trusted, and not that the schema matches the data; those
# answers live in the pipelines and the schema checks, not in
# policy. Every accessor here guards its input before touching
# object fields — a malformed document must produce findings, never
# a WASM trap.
package datacontract

import rego.v1

import data.datacontract.lib

# --- the input documents ------------------------------------------------------

contract_doc := v if {
	is_object(input)
	v := object.get(input, "contract", null)
}

contract_doc := null if not is_object(input)

evidence_doc := v if {
	is_object(input)
	v := object.get(input, "enforcement", null)
}

evidence_doc := null if not is_object(input)

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
	v := object.get(input, "contractFile", "the data contract")
}

contract_file := "the data contract" if not is_object(input)

enforcement_file := v if {
	is_object(input)
	v := object.get(input, "enforcementFile", "the enforcement record")
}

enforcement_file := "the enforcement record" if not is_object(input)

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

# A positive integer — the contract's own version and the record's
# are whole numbers.
is_positive_integer(v) if {
	is_number(v)
	v == floor(v)
	v > 0
}

# A positive number — an SLA of zero hours is no SLA at all.
is_positive_number(v) if {
	is_number(v)
	v > 0
}

# --- the contract: its house stamps -------------------------------------------

contract_version := object.get(contract_doc, "version", null)

contract_reviewed_on := object.get(contract_doc, "reviewedOn", null)

contract_owner := object.get(contract_doc, "owner", null)

# The dataset the contract governs: the join key the enforcement
# record must answer for.
dataset_name := object.get(contract_doc, "dataset", null)

# --- the contract: the schema clause ---------------------------------------------

# The machine-checkable schema the dataset is bound to, guarded: an
# object or nothing. A schema clause that is not an object is a
# finding, never a trap.
schema_doc := v if {
	is_object(contract_doc)
	v := object.get(contract_doc, "schema", null)
	is_object(v)
}

schema_doc := null if {
	is_object(contract_doc)
	not is_object(object.get(contract_doc, "schema", null))
}

schema_doc := null if not is_object(contract_doc)

schema_ref := object.get(schema_doc, "ref", null)

schema_subject := object.get(schema_doc, "subject", null)

# --- the contract: the freshness clause -------------------------------------------

freshness_doc := v if {
	is_object(contract_doc)
	v := object.get(contract_doc, "freshness", null)
	is_object(v)
}

freshness_doc := null if {
	is_object(contract_doc)
	not is_object(object.get(contract_doc, "freshness", null))
}

freshness_doc := null if not is_object(contract_doc)

# The freshness SLA, in hours: how stale the dataset may be before
# the contract is breached. The one number the freshness clause
# exists to carry.
freshness_sla := object.get(freshness_doc, "slaHours", null)

# --- the contract: the quality thresholds --------------------------------------------

quality_rows := [q | some q in as_array(contract_doc, "quality"); is_object(q)]

quality_metric(q) := object.get(q, "metric", null)

quality_min(q) := object.get(q, "min", null)

quality_max(q) := object.get(q, "max", null)

# How many of the two bound fields the row carries. A threshold row
# bounds a metric exactly one way — a row with both bounds is not a
# tighter promise, it is a promise nobody can read.
quality_bound_count(q) := count([k | some k in {"min", "max"}; object.get(q, k, null) != null])

# --- the contract: the consumers ---------------------------------------------

consumer_rows := [c | some c in as_array(contract_doc, "consumers"); is_object(c)]

consumer_name(c) := object.get(c, "name", null)

consumer_use(c) := object.get(c, "use", null)

# --- the contract: the checks that enforce it in CI -------------------------------

check_rows := [c | some c in as_array(contract_doc, "enforcement"); is_object(c)]

check_name(c) := object.get(c, "check", null)

check_pipeline(c) := object.get(c, "pipeline", null)

# --- the contract: the changes clause ---------------------------------------------

changes_doc := v if {
	is_object(contract_doc)
	v := object.get(contract_doc, "changes", null)
	is_object(v)
}

changes_doc := null if {
	is_object(contract_doc)
	not is_object(object.get(contract_doc, "changes", null))
}

changes_doc := null if not is_object(contract_doc)

# The expand-migrate-contract discipline, from the evolving-schemas
# sibling chapter: additive changes land on the same version,
# breaking changes ship as a new version side by side, and the old
# one is dropped in its own late, reviewed change after a
# deprecation window measured in days — never a calendar date.
changes_methodology := object.get(changes_doc, "methodology", null)

changes_deprecation_days := object.get(changes_doc, "deprecationWindowDays", null)

methodology_known(m) if m == "expand-migrate-contract"

# --- the enforcement record: the CI's word -------------------------------------------

# The dataset the record answers for: must equal the contract's, or
# the evidence is for somebody else's promises.
evidence_dataset := object.get(evidence_doc, "dataset", null)

run_rows := [r | some r in as_array(evidence_doc, "runs"); is_object(r)]

run_check(r) := object.get(r, "check", null)

run_on(r) := object.get(r, "ranOn", null)

# The joins the gate is built on: a check is declared when the
# contract's enforcement clause carries its name, and run when some
# row of the enforcement record carries it.
check_declared(name) if {
	some c in check_rows
	check_name(c) == name
}

check_run(name) if {
	some r in run_rows
	run_check(r) == name
}

# The latest day a check's evidence was recorded: YYYY-MM-DD strings
# sort lexicographically, so the max is the most recent run.
last_run_on(name) := max([run_on(r) |
	some r in run_rows
	run_check(r) == name
])

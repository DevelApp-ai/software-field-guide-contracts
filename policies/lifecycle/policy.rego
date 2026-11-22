# The component lifecycle record validated alone — The Software Field
# Guide, issue #105.
#
# Every finding below judges ONE document: the lifecycle record — the
# paper trail of a component's versioned transitions, the bake that
# produced its image, the patch folded in, the upgrade that replaced
# it, and the evidence each transition must carry to be believed
# (the bake's image digest, the patch's provenance, the upgrade's
# rehearsed rollback). A transition recorded once and never refreshed
# is a question, not a fact — the record's review clock and the
# review's coverage of every transition are enforced here too. The
# join lives in the gate: a record documenting a component the package
# manifest never packaged is judged where the record meets the
# manifest.
package lifecycle

import rego.v1

import data.lifecycle.lib

# --- entrypoint ----------------------------------------------------------------

validate := {
	"valid": count([f | f := validate_findings[_]; f.severity == "error"]) == 0,
	"findings": sort([f | some f in validate_findings]),
}

validate_findings := (((((((((((f_input_invalid | f_today_invalid) | f_record_missing) | f_record_stamps) | f_record_component) | f_transitions_array) | f_transitions_content) | f_transition_type) | f_transition_recorded) | f_transition_dupes) | f_bake_evidence) | f_patch_evidence) | f_upgrade_evidence

# --- findings: the input and the clock ------------------------------------------

f_input_invalid contains finding if {
	not is_object(input)
	finding := {
		"severity": "error",
		"rule": "input/invalid",
		"message": "input must be an object with the lifecycle record as input.lifecycle",
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

# --- findings: the lifecycle record document --------------------------------------

f_record_missing contains finding if {
	is_object(input)
	not is_object(lifecycle_doc)
	finding := {
		"severity": "error",
		"rule": "lifecycle/missing",
		"message": "the lifecycle record is required: pass it as input.lifecycle — one component, the transitions that produced what runs, and the evidence for each",
		"path": "$.lifecycle",
	}
}

# The record is an owned, versioned artifact: a transition recorded
# once and never refreshed is a question, not a fact.
f_record_stamps contains finding if {
	is_object(lifecycle_doc)
	not is_positive_integer(record_version)
	finding := {
		"severity": "error",
		"rule": "lifecycle/version-required",
		"message": sprintf("the lifecycle record must carry a version (a positive integer): the record is versioned like the component it tracks (%s)", [lifecycle_file]),
		"path": "$.lifecycle.version",
	}
}

f_record_stamps contains finding if {
	is_object(lifecycle_doc)
	not lib.is_valid_date(record_reviewed_on)
	finding := {
		"severity": "error",
		"rule": "lifecycle/reviewed-on-invalid",
		"message": sprintf("the lifecycle record must carry reviewedOn as a real YYYY-MM-DD date (%s)", [lifecycle_file]),
		"path": "$.lifecycle.reviewedOn",
	}
}

f_record_stamps contains finding if {
	is_object(lifecycle_doc)
	lib.is_valid_date(record_reviewed_on)
	lib.is_valid_date(today_date)
	lib.date_to_days(record_reviewed_on) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "lifecycle/reviewed-in-future",
		"message": sprintf("the lifecycle record carries a reviewedOn date in the future (%s)", [lifecycle_file]),
		"path": "$.lifecycle.reviewedOn",
	}
}

f_record_stamps contains finding if {
	is_object(lifecycle_doc)
	lib.is_valid_date(record_reviewed_on)
	lib.is_valid_date(today_date)
	lib.date_to_days(today_date) - lib.date_to_days(record_reviewed_on) > 365
	finding := {
		"severity": "error",
		"rule": "lifecycle/reviewed-stale",
		"message": sprintf("the lifecycle record was reviewed more than 365 days before today: a record nobody re-reads is a trail nobody still believes (%s)", [lifecycle_file]),
		"path": "$.lifecycle.reviewedOn",
	}
}

f_record_stamps contains finding if {
	is_object(lifecycle_doc)
	not lib.is_nonempty_string(record_owner)
	finding := {
		"severity": "error",
		"rule": "lifecycle/owner-required",
		"message": sprintf("the lifecycle record must name an owner: a paper trail without an owner is a trail nobody maintains (%s)", [lifecycle_file]),
		"path": "$.lifecycle.owner",
	}
}

# The record names the component it tracks — the join's first
# question, and a finding the gate cites before any transition is
# judged.
f_record_component contains finding if {
	is_object(lifecycle_doc)
	not lib.is_nonempty_string(record_component)
	finding := {
		"severity": "error",
		"rule": "lifecycle/component-required",
		"message": sprintf("the lifecycle record must name the component it tracks: a record for no component is a trail that belongs to nothing in particular (%s)", [lifecycle_file]),
		"path": "$.lifecycle.component",
	}
}

# --- findings: the recorded transitions -------------------------------------------

f_transitions_array contains finding if {
	is_object(lifecycle_doc)
	not is_array(object.get(lifecycle_doc, "transitions", null))
	finding := {
		"severity": "error",
		"rule": "transitions/must-be-array",
		"message": sprintf("the transitions must be an array of {type, recordedOn, ...evidence} rows (%s)", [lifecycle_file]),
		"path": "$.lifecycle.transitions",
	}
}

f_transitions_array contains finding if {
	is_object(lifecycle_doc)
	is_array(object.get(lifecycle_doc, "transitions", null))
	count(as_array(lifecycle_doc, "transitions")) == 0
	finding := {
		"severity": "error",
		"rule": "transitions/rows-required",
		"message": sprintf("the lifecycle record must carry at least one transition: a record that never moved is a component nobody ever built (%s)", [lifecycle_file]),
		"path": "$.lifecycle.transitions",
	}
}

f_transitions_content contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	not is_object(x)
	finding := {
		"severity": "error",
		"rule": "transitions/row-must-be-object",
		"message": sprintf("transition entry %d must be an object with its type, recordedOn, and the evidence that type demands (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d]", [i]),
	}
}

# --- findings: the transition's type and stamp -------------------------------------

f_transition_type contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	not lib.is_nonempty_string(transition_type(x))
	finding := {
		"severity": "error",
		"rule": "transition/type-required",
		"message": sprintf("the transition at index %d must name its type — bake, patch, or upgrade: a transition of no type is a fact of no kind (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].type", [i]),
	}
}

f_transition_type contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	lib.is_nonempty_string(transition_type(x))
	not transition_type_known(transition_type(x))
	finding := {
		"severity": "error",
		"rule": "transition/type-unknown",
		"message": sprintf("the transition at index %d carries type '%s', which the gate does not vouch for: bake, patch, upgrade — anything else is a fact this gate cannot judge (%s)", [i, transition_type(x), lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].type", [i]),
	}
}

f_transition_recorded contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	not lib.is_nonempty_string(transition_recorded_on(x))
	finding := {
		"severity": "error",
		"rule": "transition/recorded-on-required",
		"message": sprintf("the transition at index %d must carry recordedOn as a real YYYY-MM-DD date: a transition that cannot say when it happened is a fact that cannot age (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].recordedOn", [i]),
	}
}

f_transition_recorded contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	lib.is_nonempty_string(transition_recorded_on(x))
	not lib.is_valid_date(transition_recorded_on(x))
	finding := {
		"severity": "error",
		"rule": "transition/recorded-on-invalid",
		"message": sprintf("the transition at index %d carries a recordedOn stamp that is not a real calendar date: a stamp like '%v' is a date nobody can age or order (%s)", [i, transition_recorded_on(x), lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].recordedOn", [i]),
	}
}

f_transition_recorded contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	lib.is_valid_date(transition_recorded_on(x))
	lib.is_valid_date(today_date)
	lib.date_to_days(transition_recorded_on(x)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "transition/recorded-in-future",
		"message": sprintf("the transition at index %d carries a recordedOn date in the future (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].recordedOn", [i]),
	}
}

# The review must cover every transition on it: a transition recorded
# after the review is a fact nobody re-checked.
f_transition_recorded contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	lib.is_valid_date(transition_recorded_on(x))
	lib.is_valid_date(record_reviewed_on)
	lib.date_to_days(transition_recorded_on(x)) > lib.date_to_days(record_reviewed_on)
	finding := {
		"severity": "error",
		"rule": "transition/recorded-after-review",
		"message": sprintf("the transition at index %d was recorded %s, after the record's review on %s: either the review forgot a transition it should have seen, or the record back-filled a fact nobody re-checked (%s)", [i, transition_recorded_on(x), record_reviewed_on, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].recordedOn", [i]),
	}
}

# The same transition type recorded on the same day twice: evidence
# that cannot be told apart is evidence nobody can count.
f_transition_dupes contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	lib.is_nonempty_string(transition_type(x))
	lib.is_valid_date(transition_recorded_on(x))
	count([y |
		some y in as_array(lifecycle_doc, "transitions")
		is_object(y)
		transition_type(y) == transition_type(x)
		transition_recorded_on(y) == transition_recorded_on(x)
	]) > 1
	finding := {
		"severity": "error",
		"rule": "transition/duplicate",
		"message": sprintf("a %s recorded on %s appears more than once: one transition, one row — the same type and date twice is a record that cannot be diffed (%s)", [transition_type(x), transition_recorded_on(x), lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d]", [i]),
	}
}

# --- findings: the bake evidence ---------------------------------------------------

# A bake without its image digest is an image nobody can pin: the
# digest is the whole point of the bake.
f_bake_evidence contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	transition_type(x) == "bake"
	not lib.is_nonempty_string(bake_image_digest(x))
	finding := {
		"severity": "error",
		"rule": "transition/bake-digest-required",
		"message": sprintf("the bake recorded at index %d must carry the sha256 image digest it produced: a bake with no digest is an image nobody can pin to what actually runs (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].imageDigest", [i]),
	}
}

f_bake_evidence contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	transition_type(x) == "bake"
	lib.is_nonempty_string(bake_image_digest(x))
	not is_artifact_digest(bake_image_digest(x))
	finding := {
		"severity": "error",
		"rule": "transition/bake-digest-malformed",
		"message": sprintf("the bake recorded at index %d carries an image digest that is not a well-formed sha256 (64 lowercase hex characters): half a digest pins nothing (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].imageDigest", [i]),
	}
}

# --- findings: the patch evidence --------------------------------------------------

# A patch without provenance is a change nobody authored: the
# provenance names the source and the commit that made it.
f_patch_evidence contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	transition_type(x) == "patch"
	patch_provenance_doc(x) == null
	finding := {
		"severity": "error",
		"rule": "transition/patch-provenance-required",
		"message": sprintf("the patch recorded at index %d must carry provenance as an object with the source and the commit: a patch with no provenance is a change nobody authored (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].provenance", [i]),
	}
}

f_patch_evidence contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	transition_type(x) == "patch"
	patch_provenance_doc(x) != null
	not lib.is_nonempty_string(provenance_source(x))
	finding := {
		"severity": "error",
		"rule": "transition/patch-provenance-source-required",
		"message": sprintf("the patch recorded at index %d must name the source repository its change came from (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].provenance.source", [i]),
	}
}

f_patch_evidence contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	transition_type(x) == "patch"
	patch_provenance_doc(x) != null
	not lib.is_nonempty_string(provenance_commit(x))
	finding := {
		"severity": "error",
		"rule": "transition/patch-provenance-commit-required",
		"message": sprintf("the patch recorded at index %d must name the commit its change was built from: a patch pinned to no commit is a change that can point anywhere (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].provenance.commit", [i]),
	}
}

# --- findings: the upgrade evidence ------------------------------------------------

# An upgrade nobody rehearsed the rollback for is a bet, not a
# transition: the rehearsal is the upgrade's insurance.
f_upgrade_evidence contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	transition_type(x) == "upgrade"
	upgrade_rollback_doc(x) == null
	finding := {
		"severity": "error",
		"rule": "transition/upgrade-rollback-required",
		"message": sprintf("the upgrade recorded at index %d must carry rollback as an object with the rehearsedOn date of its rehearsal: an upgrade nobody rehearsed the way back for is a bet, not a transition (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].rollback", [i]),
	}
}

f_upgrade_evidence contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	transition_type(x) == "upgrade"
	upgrade_rollback_doc(x) != null
	not lib.is_nonempty_string(rollback_rehearsed_on(x))
	finding := {
		"severity": "error",
		"rule": "transition/upgrade-rehearsed-on-required",
		"message": sprintf("the upgrade recorded at index %d must carry the rehearsal date of its rollback: a rehearsal that cannot say when it happened is a rehearsal nobody can trust to still be true (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].rollback.rehearsedOn", [i]),
	}
}

f_upgrade_evidence contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	transition_type(x) == "upgrade"
	upgrade_rollback_doc(x) != null
	lib.is_nonempty_string(rollback_rehearsed_on(x))
	not lib.is_valid_date(rollback_rehearsed_on(x))
	finding := {
		"severity": "error",
		"rule": "transition/upgrade-rehearsed-on-invalid",
		"message": sprintf("the upgrade recorded at index %d carries a rollback rehearsal date that is not a real YYYY-MM-DD date (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].rollback.rehearsedOn", [i]),
	}
}

f_upgrade_evidence contains finding if {
	some i, x in as_array(lifecycle_doc, "transitions")
	is_object(x)
	transition_type(x) == "upgrade"
	upgrade_rollback_doc(x) != null
	lib.is_valid_date(rollback_rehearsed_on(x))
	lib.is_valid_date(today_date)
	lib.date_to_days(rollback_rehearsed_on(x)) > lib.date_to_days(today_date)
	finding := {
		"severity": "error",
		"rule": "transition/upgrade-rehearsed-in-future",
		"message": sprintf("the upgrade recorded at index %d carries a rollback rehearsal date in the future: a way back rehearsed tomorrow is a way back nobody has walked (%s)", [i, lifecycle_file]),
		"path": sprintf("$.lifecycle.transitions[%d].rollback.rehearsedOn", [i]),
	}
}

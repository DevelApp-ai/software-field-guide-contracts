# Instrumentation linter — The Software Field Guide, issue #61.
#
# Judges a scan of instrumentation code against the two declared
# vocabularies: an event name that is not in the vocabulary, a metric
# the label schema never declared, and — the label accretion the
# chapter warns returns silently — a label emitted on a metric whose
# label set never grew to include it. Every finding cites the
# instrumentation file and line, so the PR comment lands exactly where
# the call is.
#
# Input (JSON): {"vocabulary": {...}, "labels": {...}, "scan":
#                {"calls": [{"file", "line", "kind", "name", "labels"}]}}
# Result:       {"valid": bool, "findings": [{severity, rule, message, path}]}
package obs

import rego.v1

import data.obs.lib

# --- entrypoint -------------------------------------------------------------

lint := result if {
	fs := sort([f | some f in lint_findings])
	result := {
		"valid": count([f | f := fs[_]; f.severity == "error"]) == 0,
		"findings": fs,
	}
}

lint_findings := ((((f_input_invalid | f_vocab_missing) | f_schema_missing) | f_scan_missing) | f_scan_shape) | f_lint

# --- findings: the scan itself must be readable ------------------------------------

f_scan_missing contains finding if {
	not is_object(scan_doc)
	finding := {
		"severity": "error",
		"rule": "scan/missing",
		"message": "the instrumentation scan is required: pass it as input.scan (produced by scan/scan_instrumentation.py)",
		"path": "$.scan",
	}
}

f_scan_shape contains finding if {
	is_object(scan_doc)
	not is_array(object.get(scan_doc, "calls", null))
	finding := {
		"severity": "error",
		"rule": "scan/calls-must-be-array",
		"message": "scan.calls must be an array of {file, line, kind, name, labels} entries",
		"path": "$.scan.calls",
	}
}

f_scan_shape contains finding if {
	some i, call in scan_calls
	not is_object(call)
	finding := {
		"severity": "error",
		"rule": "scan/call-must-be-object",
		"message": sprintf("scan call %d must be an object with file, line, kind, name, and labels", [i]),
		"path": sprintf("$.scan.calls[%d]", [i]),
	}
}

f_scan_shape contains finding if {
	some i, call in scan_calls
	is_object(call)
	not call_kind(call) in {"event", "metric"}
	finding := {
		"severity": "error",
		"rule": "scan/call-kind-invalid",
		"message": sprintf("scan call %d must carry kind 'event' or 'metric'", [i]),
		"path": sprintf("$.scan.calls[%d].kind", [i]),
	}
}

f_scan_shape contains finding if {
	some i, call in scan_calls
	is_object(call)
	call_kind(call) in {"event", "metric"}
	not lib.is_nonempty_string(call_name(call))
	finding := {
		"severity": "error",
		"rule": "scan/call-name-required",
		"message": sprintf("scan call %d must carry a non-empty name", [i]),
		"path": sprintf("$.scan.calls[%d].name", [i]),
	}
}

f_scan_shape contains finding if {
	some i, call in scan_calls
	is_object(call)
	call_kind(call) in {"event", "metric"}
	not lib.is_nonempty_string(call_file(call))
	finding := {
		"severity": "error",
		"rule": "scan/call-file-required",
		"message": sprintf("scan call %d must cite the instrumentation file it came from", [i]),
		"path": sprintf("$.scan.calls[%d].file", [i]),
	}
}

f_scan_shape contains finding if {
	some i, call in scan_calls
	is_object(call)
	call_kind(call) in {"event", "metric"}
	not is_positive_integer(call_line(call))
	finding := {
		"severity": "error",
		"rule": "scan/call-line-required",
		"message": sprintf("scan call %d must cite the line of the instrumentation call (a positive integer)", [i]),
		"path": sprintf("$.scan.calls[%d].line", [i]),
	}
}

f_scan_shape contains finding if {
	some i, call in scan_calls
	is_object(call)
	call_kind(call) in {"event", "metric"}
	not is_array(call_labels(call))
	finding := {
		"severity": "error",
		"rule": "scan/call-labels-must-be-array",
		"message": sprintf("scan call %d must carry its label keys as an array (empty for events)", [i]),
		"path": sprintf("$.scan.calls[%d].labels", [i]),
	}
}

f_scan_shape contains finding if {
	some i, call in scan_calls
	is_object(call)
	call_kind(call) in {"event", "metric"}
	is_array(call_labels(call))
	some l in call_labels(call)
	not lib.is_nonempty_string(l)
	finding := {
		"severity": "error",
		"rule": "scan/call-label-invalid",
		"message": sprintf("scan call %d carries a non-string label key", [i]),
		"path": sprintf("$.scan.calls[%d].labels", [i]),
	}
}

# --- findings: the declarations ------------------------------------------------------

f_lint contains finding if {
	is_object(vocab_doc)
	some i, call in scan_calls
	call_well_formed(call)
	call_kind(call) == "event"
	not call_name(call) in vocab_event_names
	finding := {
		"severity": "error",
		"rule": "lint/event-undeclared",
		"message": sprintf("event '%s' emitted at %s:%d is not in the event vocabulary", [call_name(call), call_file(call), call_line(call)]),
		"path": sprintf("$.scan.calls[%d]", [i]),
	}
}

f_lint contains finding if {
	is_object(schema_doc)
	some i, call in scan_calls
	call_well_formed(call)
	call_kind(call) == "metric"
	not call_name(call) in schema_metric_names
	finding := {
		"severity": "error",
		"rule": "lint/metric-undeclared",
		"message": sprintf("metric '%s' emitted at %s:%d is not declared in the label schema", [call_name(call), call_file(call), call_line(call)]),
		"path": sprintf("$.scan.calls[%d]", [i]),
	}
}

# The label accretion rule: each undeclared label on a declared metric
# is its own finding, so every accretion gets its own review comment.
f_lint contains finding if {
	is_object(schema_doc)
	some i, call in scan_calls
	call_well_formed(call)
	call_kind(call) == "metric"
	schema_metric_known(call_name(call))
	some l in call_labels(call)
	not l in declared_labels(call_name(call))
	finding := {
		"severity": "error",
		"rule": "lint/label-undeclared",
		"message": sprintf("label '%s' on metric '%s' emitted at %s:%d is not in the metric's label schema (%s)", [
			l,
			call_name(call),
			call_file(call),
			call_line(call),
			concat(", ", sort([x | some x in declared_labels(call_name(call))])),
		]),
		"path": sprintf("$.scan.calls[%d]", [i]),
	}
}

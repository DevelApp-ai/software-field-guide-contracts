package authz.lib_test

import rego.v1

import data.authz.lib

test_exact_match if {
	lib.wildcard_match("order.read", "order.read")
}

test_exact_match_is_not_a_prefix_match if {
	not lib.wildcard_match("order.read", "order.read.extra")
}

test_trailing_star_matches_prefix if {
	lib.wildcard_match("orders-*", "orders-1041")
}

test_trailing_star_requires_the_prefix if {
	not lib.wildcard_match("orders-*", "carts-1041")
}

test_bare_star_matches_everything if {
	lib.wildcard_match("*", "anything at all")
}

test_star_in_prefix_matches_the_prefix if {
	# "order.*" ends in a star, so the matcher sees prefix "order." —
	# the compiler rejects such patterns up front (see is_pattern), but
	# the matcher itself stays simple: trailing star means prefix.
	lib.wildcard_match("order.*", "order.read")
}

test_is_pattern_rejects_mid_string_star if {
	# The validator's pattern gate: a star anywhere but the very end is
	# not a legal pattern in the policy language.
	not data.authz.is_pattern("order.*.read")
}

test_star_only_matches_at_the_end if {
	not lib.wildcard_match("orders-*", "orders")
}

test_wildcard_never_matches_a_non_string if {
	not lib.wildcard_match("orders-*", 1041)
}

test_nonempty_string if {
	lib.is_nonempty_string("order.read")
}

test_whitespace_only_string_is_empty if {
	not lib.is_nonempty_string("   ")
}

# The date helpers are a verbatim copy of the estate lib; these pin the
# parity so the two never drift.
test_epoch_is_day_zero if {
	lib.date_to_days("1970-01-01") == 0
}

test_consecutive_days if {
	lib.date_to_days("2026-10-20") - lib.date_to_days("2026-10-19") == 1
}

test_impossible_date_rejected if {
	not lib.is_valid_date("2026-02-30")
}

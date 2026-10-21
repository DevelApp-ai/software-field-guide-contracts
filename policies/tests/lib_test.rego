package estate.lib_test

import rego.v1

import data.estate.lib

test_epoch_is_day_zero if {
	lib.date_to_days("1970-01-01") == 0
}

test_known_anchor_2000_03_01 if {
	lib.date_to_days("2000-03-01") == 11017
}

test_consecutive_days if {
	lib.date_to_days("2026-10-20") - lib.date_to_days("2026-10-19") == 1
}

test_year_rolls_over if {
	lib.date_to_days("2027-01-01") - lib.date_to_days("2026-12-31") == 1
}

test_leap_day_rolls_over if {
	lib.date_to_days("2024-03-01") - lib.date_to_days("2024-02-29") == 1
}

test_leap_day_valid_in_leap_year if {
	lib.is_valid_date("2024-02-29")
}

test_leap_day_invalid_in_normal_year if {
	not lib.is_valid_date("2026-02-29")
}

test_day_beyond_month_end if {
	not lib.is_valid_date("2026-04-31")
	not lib.is_valid_date("2026-06-31")
	not lib.is_valid_date("2026-02-30")
}

test_format_enforced if {
	not lib.is_valid_date("2026-9-15")
	not lib.is_valid_date("15/09/2026")
	not lib.is_valid_date("2026-13-01")
	not lib.is_valid_date("2026-00-10")
	not lib.is_valid_date("")
	not lib.is_valid_date(20261020)
	not lib.is_valid_date(null)
}

test_nonempty_strings if {
	lib.is_nonempty_string("checkout")
	lib.is_nonempty_string("  checkout  ")
	not lib.is_nonempty_string("")
	not lib.is_nonempty_string("   ")
	not lib.is_nonempty_string(null)
	not lib.is_nonempty_string(7)
}

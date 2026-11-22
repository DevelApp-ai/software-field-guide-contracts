# Shared helpers for the component lifecycle evidence policies — a
# verbatim copy of the estate lib (the authz, obs, alerts, erasure,
# segment, ingress, citizen, component, and matrix tools carry the
# same copy; the lib tests pin the parity so the eleven never drift).
#
# Dates are handled with pure arithmetic: the policies never call the
# `time.*` builtins, so validation stays deterministic (the clock is
# injected as `today`) and wasm-safe (malformed user strings can never
# crash the evaluation — every date is regex- and calendar-validated
# before any arithmetic runs).
package lifecycle.lib

import rego.v1

# --- strings --------------------------------------------------------------

# True when `v` is a string with at least one non-space character.
is_nonempty_string(v) if {
	is_string(v)
	trim_space(v) != ""
}

# --- dates ----------------------------------------------------------------

# True when `v` is a YYYY-MM-DD string naming a real calendar date.
is_valid_date(v) if {
	is_string(v)
	regex.match(`^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$`, v)
	days_in_month(year_of(v), month_of(v)) >= day_of(v)
}

year_of(v) := to_number(substring(v, 0, 4))

month_of(v) := to_number(substring(v, 5, 2))

day_of(v) := to_number(substring(v, 8, 2))

# Days since 1970-01-01 for a validated YYYY-MM-DD date
# (Howard Hinnant's days_from_civil algorithm).
date_to_days(v) := days if {
	yy := year_of(v) - year_offset(month_of(v))
	mm := month_index(month_of(v))
	era := floor(yy / 400)
	yoe := yy - (era * 400)
	doy := (floor(((153 * mm) + 2) / 5) + day_of(v)) - 1
	doe := (((yoe * 365) + floor(yoe / 4)) - floor(yoe / 100)) + doy
	days := ((era * 146097) + doe) - 719468
}

# March is month zero of the shifted year.
month_index(m) := m - 3 if m > 2

month_index(m) := m + 9 if m <= 2

year_offset(m) := 1 if m <= 2

year_offset(m) := 0 if m > 2

leap_year(y) if {
	y % 4 == 0
	y % 100 != 0
}

leap_year(y) if y % 400 == 0

days_in_month(y, m) := 29 if {
	m == 2
	leap_year(y)
}

days_in_month(y, m) := 28 if {
	m == 2
	not leap_year(y)
}

days_in_month(y, m) := 30 if m in {4, 6, 9, 11}

days_in_month(y, m) := 31 if m in {1, 3, 5, 7, 8, 10, 12}

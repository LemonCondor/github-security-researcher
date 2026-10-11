package app

import "strings"

// Motif F: length guard written on a variable holding len(var) (gopsutil net_darwin.go parseNetstatLine shape).

// F1 var block alias, guard before the access
func F1(line string) string {
	var (
		columns       = strings.Fields(line)
		numberColumns = len(columns)
	)
	if numberColumns < 11 || numberColumns > 13 {
		return ""
	}
	return columns[10] // SAFE
}

// F2 short declaration alias
func F2(s string) string {
	p := strings.Split(s, ":")
	n := len(p)
	if n != 3 {
		return ""
	}
	return p[2] // SAFE
}

// F3 alias guard too weak for the index
func F3(s string) string {
	p := strings.Split(s, ":")
	n := len(p)
	if n < 2 {
		return ""
	}
	return p[2] // WANT: BUG_CANDIDATE
}

// F4 alias reassigned before the guard: no longer len(p)
func F4(s string) string {
	p := strings.Split(s, ":")
	n := len(p)
	n = 5
	if n < 5 {
		return ""
	}
	return p[3] // WANT: BUG_CANDIDATE
}

// F5 alias taken from an earlier value of the slice
func F5(s, t string) string {
	p := strings.Split(s, ":")
	n := len(p)
	p = strings.Split(t, ":")
	if n < 3 {
		return ""
	}
	return p[2] // WANT: BUG_CANDIDATE
}

// F6 alias of another slice
func F6(s, t string) string {
	p := strings.Split(s, ":")
	q := strings.Split(t, ":")
	n := len(q)
	if n < 3 {
		return ""
	}
	return p[2] // WANT: BUG_CANDIDATE
}

package app

import "strings"

// Motif B: the separator is known to be present in the split input.

func B1(s string) string {
	if strings.Contains(s, ":") {
		p := strings.Split(s, ":")
		return p[1] // SAFE
	}
	return ""
}

// one separator present proves 2 elements, not 3
func B2(s string) string {
	if strings.Contains(s, ":") {
		p := strings.Split(s, ":")
		return p[2] // WANT: BUG_CANDIDATE
	}
	return ""
}

// another separator was checked
func B3(s string) string {
	if strings.Contains(s, "=") {
		return strings.Split(s, ":")[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// kompose compose.go:301 shape: check on a simple alias of the split input
func B4(port string) (string, string) {
	value, proto := port, "tcp"
	v := port
	if strings.Contains(v, "/") {
		parts := strings.Split(port, "/")
		value = parts[0]
		proto = parts[1] // SAFE
	}
	return value, proto
}

// the split input is reassigned after the alias was taken: the alias no longer proves anything
func B5(s, other string) string {
	v := s
	s = other
	if strings.Contains(v, "/") {
		return strings.Split(s, "/")[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// gonids parser.go:233 shape, if form: HasPrefix with a prefix containing the separator
func B6(v string) string {
	if strings.HasPrefix(v, "bytes") {
		return strings.SplitAfter(v, "bytes")[1] // SAFE
	}
	return ""
}

// check on another variable
func B7(s, t string) string {
	if strings.Contains(t, ":") {
		return strings.Split(s, ":")[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// check in a branch that does not cover the access
func B8(s string) string {
	n := 0
	if strings.Contains(s, ":") {
		n++
	}
	_ = n
	return strings.Split(s, ":")[1] // WANT: BUG_CANDIDATE
}

// early exit when the separator is absent
func B9(s string) string {
	if !strings.Contains(s, "=") {
		return ""
	}
	return strings.SplitN(s, "=", 2)[1] // SAFE
}

// SplitN with n=1 never splits, whatever the input contains
func B10(s string) string {
	if strings.Contains(s, "=") {
		return strings.SplitN(s, "=", 1)[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// Count proves the number of elements
func B11(s string) string {
	if strings.Count(s, ",") >= 2 {
		p := strings.Split(s, ",")
		return p[2] // SAFE
	}
	return ""
}

// early exit through a custom validator: cannot be proven, kept for a human
func B12(s string) string {
	if !valid(s) {
		return ""
	}
	return strings.SplitN(s, "=", 2)[1] // WANT: NEEDS_REVIEW
}

func valid(s string) bool { return len(s) > 2 }

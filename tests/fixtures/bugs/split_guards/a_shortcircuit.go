package app

import "strings"

// Motif A: guards inside the same boolean expression (Go evaluates && / || left to right, short-circuit).

// kompose compose.go:133 shape
func A1(s string) bool {
	p := strings.Split(s, ":")
	return len(p) == 2 && p[1] != p[0] // SAFE
}

// gonids parser.go:337 shape
func A2(s string) string {
	p := strings.Split(s, ":")
	if len(p) < 2 || p[1] == "" { // SAFE
		return ""
	}
	return p[1] // SAFE
}

// insufficient guard on the left of &&
func A3(s string) bool {
	p := strings.Split(s, ":")
	return len(p) > 0 && p[1] != "" // WANT: BUG_CANDIDATE
}

// guard written AFTER the access: evaluated too late
func A4(s string) bool {
	p := strings.Split(s, ":")
	return p[1] != "" && len(p) == 2 // WANT: BUG_CANDIDATE
}

// || : the right side runs exactly when len(p) != 2
func A5(s string) bool {
	p := strings.Split(s, ":")
	return len(p) == 2 || p[1] != "" // WANT: BUG_CANDIDATE
}

// nested parentheses
func A6(s string, ok bool) bool {
	p := strings.Split(s, ":")
	return ok && (len(p) > 1 && p[1] == "a") // SAFE
}

// negated guard: the right side runs when len(p) <= 1
func A7(s string) bool {
	p := strings.Split(s, ":")
	return !(len(p) > 1) && p[1] == "a" // WANT: BUG_CANDIDATE
}

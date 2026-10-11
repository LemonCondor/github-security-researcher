package app

import "strings"

// Motif C: tagless switch. A case runs only when every earlier case is false.

// go-github example/commitpr/main.go:128 shape
func C1(arg string) (string, string) {
	f := strings.Split(arg, ":")
	switch {
	case len(f) < 1:
		return "", ""
	case len(f) == 1:
		return f[0], f[0]
	default:
		return f[0], f[1] // SAFE
	}
}

// default only excludes len==1 and len>5: len 0 is still possible for Fields
func C2(arg string) string {
	f := strings.Fields(arg)
	switch {
	case len(f) == 1:
		return "one"
	case len(f) > 5:
		return f[5] // SAFE
	default:
		return f[1] // WANT: BUG_CANDIDATE
	}
}

// gonids parser.go:1037 shape: case on Contains
func C3(v string) string {
	switch {
	case v == "only":
		return ""
	case strings.Contains(v, ","):
		s := strings.Split(v, ",")
		return s[1] // SAFE
	}
	return ""
}

// a case list is a disjunction: nothing is proven
func C4(arg string) string {
	f := strings.Split(arg, ":")
	switch {
	case len(f) > 1, f[0] == "x":
		return f[1] // WANT: NEEDS_REVIEW
	}
	return ""
}

// a length check in ANOTHER case does not protect this one
func C5(arg string) string {
	f := strings.Split(arg, ":")
	switch {
	case len(f) > 1:
		return "many"
	case arg != "":
		return f[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

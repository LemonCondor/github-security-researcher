package app

import "strings"

// the input is validated before the split: may be safe, needs a human
func Validated(s string) string {
	if !strings.Contains(s, "=") {
		return ""
	}
	parts := strings.SplitN(s, "=", 2)
	return parts[1]
}

// bound compared to a non-constant value
func Bounded(s string, n int) string {
	parts := strings.Split(s, ",")
	if len(parts) < n {
		return ""
	}
	return parts[1]
}

// the slice variable is redefined between the split and the index
func Redefined(s string, other []string, flag bool) string {
	parts := strings.Split(s, ",")
	if flag {
		parts = other
	}
	return parts[1]
}

// non-constant separator: index 0 only fails for an empty separator AND empty input (cf. ntfy util.go:92)
func SplitKV(s, sep string) string {
	kv := strings.SplitN(s, sep, 2)
	return kv[0]
}

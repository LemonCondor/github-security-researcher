package app

import (
	"errors"
	"strings"
)

// SplitN result indexed without any length check: "novalue" panics (cf. direnv #1496)
func ParseKV(s string) (string, string) {
	parts := strings.SplitN(s, "=", 2)
	return parts[0], parts[1]
}

// guard present but insufficient: Split never returns an empty slice (cf. kong #623)
func Port(addr string) (string, error) {
	parts := strings.Split(addr, ":")
	if len(parts) == 0 {
		return "", errors.New("empty")
	}
	return parts[1], nil
}

// Fields can return an empty slice: a blank line panics
func Command(line string) string {
	return strings.Fields(line)[0]
}

// direct index on the split call
func Minor(version string) string {
	return strings.Split(version, ".")[1]
}

// a check on the input that does not test the separator does not protect (cf. git-sync main.go:848)
func ConfigPairs(entries []string) []string {
	var out []string
	for _, e := range entries {
		if e == "" {
			continue
		}
		parts := strings.SplitN(e, "\n", 2)
		out = append(out, parts[0], parts[1])
	}
	return out
}

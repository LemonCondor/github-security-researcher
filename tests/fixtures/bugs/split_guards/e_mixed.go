package app

import "strings"

// several accesses in one function: only the unprotected one is reported
func E1(s string) string {
	p := strings.Split(s, ":")
	out := ""
	if len(p) > 1 {
		out = p[1] // SAFE
	}
	return out + p[1] // WANT: BUG_CANDIDATE
}

// nested conditions
func E2(s string, x bool) string {
	if strings.Contains(s, ":") {
		if x {
			p := strings.Split(s, ":")
			return p[1] // SAFE
		}
	}
	return ""
}

// kompose pkg/transformer/utils.go:85 shape: len != 0 proves index 0 even with a non-constant separator
func E3(v, sep string) string {
	vs := strings.Split(v, sep)
	if len(vs) == 0 {
		return ""
	}
	return vs[0] // SAFE
}

// git-sync main.go:848 (PR #1006): only an emptiness check, no separator guarantee
func E4(stdout string) []string {
	var kvs []string
	cfgs := strings.Split(stdout, string(rune(0)))
	for _, cfg := range cfgs {
		if cfg == "" {
			continue
		}
		parts := strings.SplitN(cfg, "\n", 2)
		kvs = append(kvs, parts[0], parts[1]) // WANT: BUG_CANDIDATE
	}
	return kvs
}

package app

import (
	"errors"
	"os"
	"strings"
)

func ParseKVChecked(s string) (string, string, error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return "", "", errors.New("want key=value")
	}
	return parts[0], parts[1], nil
}

func Inside(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

func EarlyOr(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || parts[0] == "" {
		return ""
	}
	return parts[1]
}

func Switch(s string) string {
	parts := strings.Split(s, "/")
	switch len(parts) {
	case 2, 3:
		return parts[1]
	}
	return ""
}

// index 0 of Split with a non-empty separator always exists
func Head(s string) string {
	return strings.Split(s, ",")[0]
}

// constant input: the result length is known (looks like the bug, cannot panic)
func Constant() string {
	parts := strings.Split("a:b:c", ":")
	return parts[2]
}

// strings.Cut: no index at all
func Cut(s string) string {
	_, v, _ := strings.Cut(s, "=")
	return v
}

func fail(msg string) {
	println(msg)
	os.Exit(1)
}

// the guard exits through a local helper that never returns (cf. ntfy tools/fbsend/main.go:29)
func Args(args []string) map[string]string {
	m := map[string]string{}
	for _, a := range args {
		kv := strings.SplitN(a, "=", 2)
		if len(kv) != 2 {
			fail("bad argument " + a)
		}
		m[kv[0]] = kv[1]
	}
	return m
}

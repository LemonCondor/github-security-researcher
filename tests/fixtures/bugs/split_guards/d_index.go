package app

import "strings"

// Motif D: separator established through strings.Index results.

func D1(s string) string {
	i := strings.Index(s, "=")
	if i != -1 {
		return strings.SplitN(s, "=", 2)[1] // SAFE
	}
	return ""
}

func D2(s string) string {
	if strings.Index(s, ":") >= 0 {
		return strings.Split(s, ":")[1] // SAFE
	}
	return ""
}

// Index of another separator
func D3(s string) string {
	i := strings.Index(s, "=")
	if i != -1 {
		return strings.Split(s, ":")[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// the branch where the separator is ABSENT
func D4(s string) string {
	i := strings.Index(s, "=")
	if i == -1 {
		return strings.Split(s, "=")[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// kompose pkg/loader/compose/utils.go:141 shape: separator variable chosen from Index results
func D5(e string) (string, string) {
	equalPos := strings.Index(e, "=")
	colonPos := strings.Index(e, ":")
	character := ""
	switch {
	case equalPos == -1 && colonPos == -1:
		character = ""
	case equalPos == -1 && colonPos != -1:
		character = ":"
	case equalPos != -1 && colonPos == -1:
		character = "="
	case equalPos != -1 && colonPos != -1:
		if equalPos > colonPos {
			character = ":"
		} else {
			character = "="
		}
	}
	if character == "" {
		return e, ""
	} else {
		values := strings.SplitN(e, character, 2)
		return values[0], values[1] // SAFE
	}
}

// same, but one assignment is not backed by an Index check
func D6(e string) string {
	equalPos := strings.Index(e, "=")
	character := ""
	switch {
	case equalPos != -1:
		character = "="
	default:
		character = ";"
	}
	values := strings.SplitN(e, character, 2)
	return values[1] // WANT: BUG_CANDIDATE
}

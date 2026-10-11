package app

import "strings"

// Motif F: false-negative risks of the guard modelling. A guard must not be credited to an access it does
// not protect. Annotations: SAFE = no candidate, WANT = expected status.

// F1 guard on another variable
func F1(a, b string) string {
	parts := strings.Split(a, ":")
	vals := strings.Split(b, ":")
	if len(parts) != 2 {
		return ""
	}
	return parts[1] + vals[1] // WANT: BUG_CANDIDATE
}

// F2 early exit written after the access
func F2(s string) string {
	p := strings.Split(s, ":")
	x := p[1] // WANT: BUG_CANDIDATE
	if len(p) < 2 {
		return ""
	}
	return x
}

// F3 guard in a sibling branch only
func F3(s string, ok bool) string {
	p := strings.Split(s, ":")
	if ok {
		if len(p) < 2 {
			return ""
		}
	}
	return p[1] // WANT: BUG_CANDIDATE
}

// F4 wrong comparison direction (exit when long enough)
func F4(s string) string {
	p := strings.Split(s, ":")
	if len(p) > 1 {
		return ""
	}
	return p[1] // WANT: BUG_CANDIDATE
}

// F5 guard on the previous value: the slice is re-split after the check
func F5(s, t string) string {
	p := strings.Split(s, ":")
	if len(p) < 2 {
		return ""
	}
	p = strings.Split(t, ":")
	return p[1] // WANT: BUG_CANDIDATE
}

// F6 loop-carried value: guard before the loop, slice re-split at the end of each iteration
func F6(s string, lines []string) []string {
	var out []string
	p := strings.Split(s, ":")
	if len(p) < 2 {
		return nil
	}
	for _, l := range lines {
		out = append(out, p[1]) // WANT: NEEDS_REVIEW
		p = strings.Split(l, ":")
	}
	return out
}

// F7 same loop, guard re-evaluated inside the loop body: proven at every iteration
func F7(s string, lines []string) []string {
	var out []string
	p := strings.Split(s, ":")
	for _, l := range lines {
		if len(p) < 2 {
			continue
		}
		out = append(out, p[1]) // SAFE
		p = strings.Split(l, ":")
	}
	return out
}

// F8 a closure re-splits the slice after the guard; the access runs after the closure
func F8(s, t string) string {
	p := strings.Split(s, ":")
	if len(p) < 2 {
		return ""
	}
	reload := func() { p = strings.Split(t, ":") }
	reload()
	return p[1] // WANT: NEEDS_REVIEW
}

// F9 access inside a closure body: closures are not analysed (no claim either way; known limit)
func F9(s string) func() string {
	p := strings.Split(s, ":")
	if len(p) < 2 {
		return nil
	}
	return func() string { return p[1] }
}

// F10 separator checked on a value of the input that a loop overwrites
func F10(s string, n int) []string {
	var out []string
	if !strings.Contains(s, ":") {
		return nil
	}
	for i := 0; i < n; i++ {
		out = append(out, strings.Split(s, ":")[1]) // WANT: NEEDS_REVIEW
		s = strings.Repeat(s, i)
	}
	return out
}

// F11 strings.Index result computed on an older value of the input
func F11(s, other string) string {
	i := strings.Index(s, ":")
	s = other
	if i < 0 {
		return ""
	}
	return strings.Split(s, ":")[1] // WANT: BUG_CANDIDATE
}

// F12 same shape with the index computed on the current value
func F12(s string) string {
	i := strings.Index(s, ":")
	if i < 0 {
		return ""
	}
	return strings.Split(s, ":")[1] // SAFE
}

// F13 fallthrough into a guarded case: len(f) == 1 reaches the access
func F13(arg string) string {
	f := strings.Split(arg, ":")
	switch len(f) {
	case 1:
		fallthrough
	case 2:
		return f[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// F14 tagless switch with fallthrough
func F14(arg string) string {
	f := strings.Split(arg, ":")
	switch {
	case len(f) == 1:
		fallthrough
	case len(f) > 1:
		return f[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// F15 IndexAny finds ANY of the characters: no proof for a two-character separator
func F15(s string) string {
	if strings.IndexAny(s, ",;") >= 0 {
		return strings.Split(s, ",;")[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// F16 raw string `\n` is a backslash and an n, not a newline
func F16(s string) string {
	if strings.Contains(s, `\n`) {
		return strings.SplitN(s, "\n", 2)[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

// F17 same escape on both sides: proven
func F17(s string) string {
	if strings.Contains(s, "\n") {
		return strings.SplitN(s, "\n", 2)[1] // SAFE
	}
	return ""
}

// F18 closure body: not analysed (known limit)
func F18(s, t string) func() string {
	p := strings.Split(s, ":")
	f := func() string {
		if len(p) < 2 {
			return ""
		}
		return p[1]
	}
	p = strings.Split(t, ":")
	return f
}

// F19 guard is >= 1 for index 1 (off by one)
func F19(s string) string {
	p := strings.Split(s, ":")
	if len(p) >= 1 {
		return p[1] // WANT: BUG_CANDIDATE
	}
	return ""
}

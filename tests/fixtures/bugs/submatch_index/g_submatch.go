package app

import (
	"errors"
	"regexp"
	"strings"
)

// Motif G: index into a regexp submatch result (nil when the input does not match).
// Annotations: SAFE = no candidate, WANT = expected status.

var kvRe = regexp.MustCompile(`^(\w+)=(\w+)$`)

var (
	verRe  = regexp.MustCompile("v(\\d+)\\.(\\d+)")
	starRe = regexp.MustCompile(`(\w*)`)
)

var dynRe *regexp.Regexp

// G1 no check at all
func G1(s string) string {
	m := kvRe.FindStringSubmatch(s)
	return m[1] // WANT: BUG_CANDIDATE
}

// G2 direct call
func G2(s string) string {
	return verRe.FindStringSubmatch(s)[2] // WANT: BUG_CANDIDATE
}

// G3 nil check, index within the group count
func G3(s string) string {
	m := kvRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[2] // SAFE
}

// G4 len check (ntfy server.go:797 shape)
func G4(s string) string {
	m := kvRe.FindStringSubmatch(s)
	if len(m) != 3 {
		return ""
	}
	return m[1] // SAFE
}

// G5 nil check but index beyond the 2 groups: panics on every match
func G5(s string) string {
	m := kvRe.FindStringSubmatch(s)
	if m != nil {
		return m[3] // WANT: BUG_CANDIDATE
	}
	return ""
}

// G6 MatchString on the same regexp and the same input
func G6(s string) string {
	if !kvRe.MatchString(s) {
		return ""
	}
	return kvRe.FindStringSubmatch(s)[1] // SAFE
}

// G7 MatchString on ANOTHER input
func G7(s, t string) string {
	if !kvRe.MatchString(t) {
		return ""
	}
	return kvRe.FindStringSubmatch(s)[1] // WANT: BUG_CANDIDATE
}

// G8 MatchString with ANOTHER regexp: an unmodelled validator of the input (may or may not imply a match)
func G8(s string) string {
	if !verRe.MatchString(s) {
		return ""
	}
	return kvRe.FindStringSubmatch(s)[1] // WANT: NEEDS_REVIEW
}

// G9 pattern that matches the empty string: never nil
func G9(s string) string {
	return starRe.FindStringSubmatch(s)[1] // WANT: NEEDS_REVIEW
}

// G10 receiver of unknown origin
func G10(s string) string {
	return dynRe.FindStringSubmatch(s)[1] // WANT: NEEDS_REVIEW
}

// G11 input validated by a custom function
func G11(s string) string {
	if !validKV(s) {
		return ""
	}
	return kvRe.FindStringSubmatch(s)[1] // WANT: NEEDS_REVIEW
}

func validKV(s string) bool { return strings.Contains(s, "=") }

// G12 local regexp, len guard in the condition (short-circuit)
func G12(s string) bool {
	re := regexp.MustCompile(`a(b)`)
	m := re.FindStringSubmatch(s)
	return len(m) > 1 && m[1] == "b" // SAFE
}

// G13 guard on another match result
func G13(a, b string) string {
	m := kvRe.FindStringSubmatch(a)
	n := kvRe.FindStringSubmatch(b)
	if m == nil {
		return ""
	}
	return m[1] + n[1] // WANT: BUG_CANDIDATE
}

// G14 len(m) > 0 proves a match, hence 1 + 2 elements
func G14(s string) string {
	m := kvRe.FindStringSubmatch(s)
	if len(m) > 0 {
		return m[2] // SAFE
	}
	return ""
}

// G15 a method of another type with the same name is not judged as a regexp
type finder struct{}

func (finder) FindStringSubmatch(s string) []string { return []string{s, s} }

func G15(s string) string {
	var f finder
	return f.FindStringSubmatch(s)[1] // WANT: NEEDS_REVIEW
}

// G16 loop: match result carried from a previous iteration
func G16(lines []string) []string {
	var out []string
	m := kvRe.FindStringSubmatch("a=b")
	if m == nil {
		return nil
	}
	for _, l := range lines {
		out = append(out, m[1]) // WANT: NEEDS_REVIEW
		m = kvRe.FindStringSubmatch(l)
	}
	return out
}

// G17 index 0 still needs a match
func G17(s string) string {
	return kvRe.FindStringSubmatch(s)[0] // WANT: BUG_CANDIDATE
}

// G18 nil check whose body ends in an if/else where both branches return (pebble plan.go:1551 shape)
func G18(s string, dir bool) (string, error) {
	m := kvRe.FindStringSubmatch(s)
	if m == nil {
		if dir {
			return "", errors.New("bad dir")
		} else {
			return "", errors.New("bad file")
		}
	}
	return m[1], nil // SAFE
}

// G19 if/else inside the nil check where only one branch exits: the other falls through
func G19(s string, dir bool) (string, error) {
	m := kvRe.FindStringSubmatch(s)
	if m == nil {
		if dir {
			return "", errors.New("bad dir")
		} else {
			s = "x"
		}
	}
	return m[1], nil // WANT: BUG_CANDIDATE
}

// G20 else-if chain where every branch exits
func G20(s string, n int) (string, error) {
	m := kvRe.FindStringSubmatch(s)
	if m == nil {
		if n == 0 {
			return "", errors.New("zero")
		} else if n == 1 {
			panic("one")
		} else {
			return "", errors.New("other")
		}
	}
	return m[2], nil // SAFE
}

// G21 else-if chain without a final else: may fall through
func G21(s string, n int) (string, error) {
	m := kvRe.FindStringSubmatch(s)
	if m == nil {
		if n == 0 {
			return "", errors.New("zero")
		} else if n == 1 {
			return "", errors.New("one")
		}
	}
	return m[2], nil // WANT: BUG_CANDIDATE
}

func note() int { return 1 }

// G22 the nil branch calls a helper that returns normally: not an exit
func G22(s string) string {
	m := kvRe.FindStringSubmatch(s)
	if m == nil {
		note()
	}
	return m[1] // WANT: BUG_CANDIDATE
}

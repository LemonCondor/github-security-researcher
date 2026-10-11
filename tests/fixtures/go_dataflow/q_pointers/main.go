package app

import "example.org/lib"

// positive: source -> variable -> &x -> *p -> sink
func DerefVar(input string) {
	x := input
	p := &x
	sink(*p)
}

// positive: dereferenced value passed to another function
func DerefCall(input string) {
	p := &input
	helper(*p)
}

func helper(v string) { sink(v) }

// pointer to another variable
func OtherVar(input string) {
	other := "constant"
	p := &other
	sink(*p)
}

// pointer reassigned before the dereference
func Reassigned(input string) {
	other := "constant"
	p := &input
	p = &other
	sink(*p)
}

// pointee modified after the address was taken
func PointeeKilled(input string) {
	p := &input
	input = "constant"
	sink(*p)
}

// identity ambiguous: two possible pointees
func Ambiguous(input string, flag bool) {
	other := "constant"
	p := &other
	if flag {
		p = &input
	}
	sink(*p)
}

// pointer from an unresolved external call
func External(input string) {
	p := lib.Ptr()
	sink(*p)
}

// pointer escapes to a callee that may write through it
func Escaped(input string) {
	p := &input
	mutate(p)
	sink(*p)
}

func mutate(q *string) {}

// write through the pointer
func WriteThrough(input string) {
	p := &input
	*p = "constant"
	sink(*p)
}

// pointer parameter: pointee identity unknown
func ParamPointer(input *string) {
	sink(*input)
}

func sink(v string) {}

package app

type A struct{}
type B struct{}

func (a *A) Process(v string) { sink(v) }
func (b *B) Process(v string) { sink(v) }

var global = &A{}

func pick(flag bool) *A { return &A{} }

// Receiver comes from a call result: type not determined syntactically.
func HandlerCall(input string, flag bool) {
	p := pick(flag)
	p.Process(input)
}

// Same variable name bound to two different types in different scopes.
func HandlerShadow(input string, flag bool) {
	if flag {
		r := &A{}
		r.Process(input)
	} else {
		r := &B{}
		r.Process(input)
	}
}

// Package-level variable receiver.
func HandlerGlobal(input string) {
	global.Process(input)
}

func sink(v string) {}

type processor interface{ Process(v string) }

func pickAny(flag bool) processor { return &A{} }

// Declared result is an interface: the implementation is not provable.
func HandlerCallIface(input string, flag bool) {
	p := pickAny(flag)
	p.Process(input)
}

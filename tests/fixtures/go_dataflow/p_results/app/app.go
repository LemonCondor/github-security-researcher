package app

import (
	"strings"

	"example.com/res/a"
	"example.com/res/b"
)

type Runner struct{}

func (r *Runner) Run(v string) { sink(v) }

func (r *Runner) Hop1(v string) { r.Hop2(v) }
func (r *Runner) Hop2(v string) { r.Hop3(v) }
func (r *Runner) Hop3(v string) { r.Hop4(v) }
func (r *Runner) Hop4(v string) { sink(v) }

type Factory struct{}

func (f *Factory) NewRunner() *Runner { return &Runner{} }

type Doer interface{ Run(v string) }

type Config struct{ Command string }

type Node struct{}

func (n *Node) Next() *Node     { return n }
func (n *Node) Use(v string)    { sink(v) }
func makePtr() *Runner          { return &Runner{} }
func makeVal() Runner           { return Runner{} }
func makeIface() Doer           { return &Runner{} }
func makePair() (*Runner, error) { return &Runner{}, nil }
func makeErrFirst() (error, *Runner) { return nil, &Runner{} }
func makeGen[T any]() T          { var z T; return z }

// 1. local function returning *T
func Ptr(input string) {
	r := makePtr()
	r.Run(input)
}

// 2. local function returning T
func Val(input string) {
	r := makeVal()
	r.Run(input)
}

// 3. local method returning *T
func Method(input string) {
	f := &Factory{}
	r := f.NewRunner()
	r.Run(input)
}

// 4. call -> result -> (struct field value as argument) -> sink
func FieldToCallResult(input string) {
	c := &Config{Command: input}
	makePtr().Run(c.Command)
}

// 5. call -> result -> method -> sink
func Chain(input string) {
	makePtr().Run(input)
}

// 6. same function/type names in two packages
func OtherPkg(input string) {
	a.NewRunner().Exec(input)
	b.NewRunner().Exec(input)
}

// 7. declared result is an interface
func Iface(input string) {
	r := makeIface()
	r.Run(input)
}

// 8. ambiguous declaration (build-tag variants) / type-parameter result
func Dup(input string) {
	r := makeDup()
	r.Run(input)
}

func Generic(input string) {
	makeGen[*Runner]().Run(input)
}

// 9. external function: signature not available
func External(input string) {
	strings.NewReplacer("a", "b").Replace(input)
}

// 10. multiple results, position followed
func Pair(input string) {
	r, err := makePair()
	_ = err
	r.Run(input)
}

func ErrFirst(input string) {
	_, r := makeErrFirst()
	r.Run(input)
}

// 11. method returning its own type, chained and self-assigned
func SelfType(input string) {
	n := &Node{}
	n = n.Next()
	n.Next().Next().Use(input)
}

// 12. depth limit still applies after a call-result receiver
func Deep(input string) {
	makePtr().Hop1(input)
}

func sink(v string) {}

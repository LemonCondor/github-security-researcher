package app

type Processor interface {
	Process(v string)
}

type A struct{}

type B struct{}

func (a *A) Process(v string) { sink(v) }

func (b *B) Process(v string) {}

func Entry(input string, p Processor) {
	p.Process(input)
}

func sink(v string) {}

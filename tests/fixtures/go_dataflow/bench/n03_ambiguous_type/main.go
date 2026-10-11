package app

type A struct{}

type B struct{}

func (a *A) Process(v string) { sink(v) }

func (b *B) Process(v string) { sink(v) }

func Entry(input string, flag bool) {
	s := &A{}
	if flag {
		s := &B{}
		_ = s
	}
	s.Process(input)
}

func sink(v string) {}

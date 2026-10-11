package app

type A struct {
	Cmd string
}

type B struct {
	Cmd string
}

func Entry(input string) {
	a := &A{}
	a.Cmd = input
	b := &B{}
	b.Cmd = "constant"
	sink(b.Cmd)
}

func sink(v string) {}

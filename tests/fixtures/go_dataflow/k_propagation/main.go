package app

func Chain(input string) {
	x := input
	y := x
	Process(y)
}

func Concat(input string) {
	q := "select:" + input
	sink(q)
}

func Clean(input string) {
	w := "constant"
	sink(w)
}

func UseBeforeAssign(input string) {
	var late string
	sink(late)
	late = input
}

func Process(value string) { sink(value) }

func sink(v string) {}

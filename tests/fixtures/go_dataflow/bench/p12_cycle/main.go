package app

func Entry(input string) {
	a(input)
}

func a(v string) {
	b(v)
}

func b(v string) {
	a(v)
	sink(v)
}

func sink(v string) {}

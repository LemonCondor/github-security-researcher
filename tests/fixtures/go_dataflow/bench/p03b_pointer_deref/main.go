package app

func Entry(input string) {
	p := &input
	sink(*p)
}

func sink(v string) {}

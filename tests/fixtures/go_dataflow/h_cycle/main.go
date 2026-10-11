package app

func A(x string) {
	B(x)
}

func B(x string) {
	A(x)
	sink(x)
}

func Self(x string) {
	Self(x)
}

func sink(v string) {}

package app

func Entry(input string, flag bool) {
	x := "constant"
	if flag {
		x := input
		_ = x
	}
	sink(x)
}

func sink(v string) {}

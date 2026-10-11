package app

func Handler(input string) {
	Process(input)
}

func Process(value string) {
	sink(value)
}

func sink(v string) {}

package app

func Handler(input string) {
	Process(input)
}

func Process(value string) {
	Save(value)
}

func Save(value string) {
	sink(value)
}

func sink(v string) {}

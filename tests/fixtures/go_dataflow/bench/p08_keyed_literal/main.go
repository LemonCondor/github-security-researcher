package app

type Config struct {
	Cmd  string
	Name string
}

func Entry(input string) {
	c := Config{Name: "fixed", Cmd: input}
	sink(c.Cmd)
}

func sink(v string) {}

package app

type Config struct {
	Cmd string
}

func Entry(input string) {
	c := Config{}
	c.Cmd = input
	use(c)
}

func use(c Config) {
	sink(c.Cmd)
}

func sink(v string) {}

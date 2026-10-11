package app

type Config struct {
	Cmd string
}

func Entry(input string) {
	c1 := &Config{}
	c2 := &Config{}
	c1.Cmd = input
	c2.Cmd = "constant"
	sink(c2.Cmd)
}

func sink(v string) {}

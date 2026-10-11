package app

type Config struct {
	Cmd string
}

func Entry(input string) {
	c := &Config{}
	d := c
	d.Cmd = input
	sink(c.Cmd)
}

func sink(v string) {}

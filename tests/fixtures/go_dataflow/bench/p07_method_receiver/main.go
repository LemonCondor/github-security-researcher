package app

type Config struct {
	Cmd string
}

func Entry(input string) {
	c := &Config{}
	c.Cmd = input
	c.Run()
}

func (c *Config) Run() {
	sink(c.Cmd)
}

func sink(v string) {}

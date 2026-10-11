package app

type Inner struct {
	Cmd string
}

type Config struct {
	In Inner
}

func Entry(input string) {
	c := &Config{}
	c.In.Cmd = input
	sink(c.In.Cmd)
}

func sink(v string) {}

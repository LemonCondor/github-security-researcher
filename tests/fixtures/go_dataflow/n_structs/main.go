package app

type Config struct {
	Command string
	Name    string
}

type Other struct {
	Command string
}

type Runner interface {
	Run()
}

// 1. field of a fresh object -> sink
func FieldDirect(input string) {
	c := &Config{}
	c.Command = input
	sink(c.Command)
}

// 2. struct passed by value to another function
func PassValue(input string) {
	cfg := Config{}
	cfg.Command = input
	serviceValue(cfg)
}

func serviceValue(cfg Config) {
	sink(cfg.Command)
}

// 3. pointer to struct
func PassPointer(input string) {
	c := Config{}
	c.Command = input
	servicePtr(&c)
}

func servicePtr(c *Config) {
	sink(c.Command)
}

// keyed literal + method receiver
func Literal(input string) {
	c := &Config{Command: input}
	c.Run()
}

func (c *Config) Run() {
	sink(c.Command)
}

// 4. two struct types with the same field name; other field of the same object
func TwoTypes(input string) {
	c := &Config{}
	c.Command = input
	o := &Other{}
	o.Command = "fixed"
	sink(o.Command)
	sink(c.Name)
	useOther(o)
}

func useOther(o *Other) {
	sink(o.Command)
}

// 5. object identity unknown / type ambiguous -> NO_PROOF
func newConfig() *Config { return &Config{} }

func UnknownObject(input string) {
	c := newConfig()
	c.Command = input
	sink(c.Command)
}

func AmbiguousType(input string, flag bool) {
	if flag {
		x := &Config{}
		x.Command = input
		sink(x.Command)
	} else {
		x := &Other{}
		x.Command = input
		sink(x.Command)
	}
}

// aliasing is refused, not guessed
func Aliased(input string) {
	c := &Config{}
	c.Command = input
	y := c
	y.Command = "safe"
	sink(c.Command)
}

// 6. field reassigned with a constant / whole object replaced
func FieldKilled(input string) {
	c := &Config{}
	c.Command = input
	c.Command = "safe"
	sink(c.Command)
}

func ObjectReplaced(input string) {
	c := &Config{Command: input}
	c = &Config{}
	sink(c.Command)
}

// 7. field changed only in a branch -> may flow
func FieldBranch(input string, b bool) {
	c := &Config{Command: "safe"}
	if b {
		c.Command = input
	}
	sink(c.Command)
}

// 8. different object of the same type
func OtherObject(input string) {
	a := &Config{}
	b := &Config{}
	a.Command = input
	sink(b.Command)
	servicePtr(b)
}

// 9. unresolved interface
func ViaInterfaceParam(input string) {
	c := &Config{Command: input}
	runAny(c)
}

func runAny(r Runner) {
	r.Run()
}

// 10. comments / strings that look like field writes
func Comments(input string) {
	c := &Config{}
	// c.Command = input
	s := "c.Command = input"
	_ = s
	sink(c.Command)
}

// 11. cycle through struct-carrying calls
func Cycle(input string) {
	c := &Config{Command: input}
	cycleA(c)
}

func cycleA(c *Config) {
	cycleB(c)
}

func cycleB(c *Config) {
	cycleA(c)
	sink(c.Command)
}

// 12. depth limit
func Deep(input string) {
	c := &Config{Command: input}
	d1(c)
}

func d1(c *Config) { d2(c) }
func d2(c *Config) { d3(c) }
func d3(c *Config) { d4(c) }
func d4(c *Config) { sink(c.Command) }

func sink(v string) {}

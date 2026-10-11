package app

func Handler(input string) {
	// sink(input)
	/* Process(input) */
	s := "sink(input)"
	raw := `Process(input)`
	_, _ = s, raw
	logLine(len(input))
}

func Process(value string) { sink(value) }

func logLine(n int) {}

func sink(v string) {}

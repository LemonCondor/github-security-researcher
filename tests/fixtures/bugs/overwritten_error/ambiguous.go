package app

// a closure between the two assignments captures err: it may read the first value
func RunClosure() error {
	err := step(1)
	report := func() { println(err) }
	report()
	err = step(2)
	return err
}

// goto in the function: straight-line reasoning is not sound
func RunGoto(n int) error {
	err := step(n)
again:
	err = step(n + 1)
	if n > 10 {
		n--
		goto again
	}
	return err
}

package app

// checked before being overwritten
func RunChecked() error {
	err := step(1)
	if err != nil {
		return err
	}
	err = step(2)
	return err
}

// the overwrite reads the previous value
func RunWrapped() error {
	err := step(1)
	err = wrap(err)
	return err
}

func wrap(err error) error { return err }

// same name in a nested scope is another variable
func RunShadow(flag bool) error {
	err := step(1)
	if flag {
		err := step(2)
		_ = err
	}
	return err
}

// first value can never be non-nil: ok() returns only nil
func ok() error { return nil }

func RunNeverFails() error {
	err := ok()
	err = step(2)
	return err
}

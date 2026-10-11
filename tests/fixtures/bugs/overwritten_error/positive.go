package app

import "errors"

func step(n int) error {
	if n < 0 {
		return errors.New("negative")
	}
	return nil
}

func pair(n int) (int, error) {
	if n < 0 {
		return 0, errors.New("negative")
	}
	return n, nil
}

// the error of step(1) is overwritten before anyone reads it
func Run() error {
	err := step(1)
	err = step(2)
	return err
}

// same with a multi-value call
func RunPair() (int, error) {
	a, err := pair(1)
	b, err := pair(a)
	return b, err
}

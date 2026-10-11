package app

import "fmt"

// error checked
func PersistChecked(path string) error {
	if err := save(path); err != nil {
		return err
	}
	return nil
}

// error returned to the caller
func PersistForward(path string) error {
	return save(path)
}

// looks ignored, but touch can never fail: every return is nil
func touch() error {
	return nil
}

func Touch() {
	touch()
}

// external call: no declared signature in the module, no claim
func Log(msg string) {
	fmt.Println(msg)
}

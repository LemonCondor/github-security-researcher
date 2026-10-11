package app

import "errors"

type Store struct{ dirty bool }

func save(path string) error {
	if path == "" {
		return errors.New("empty path")
	}
	return nil
}

func (s *Store) flush() error {
	if s.dirty {
		return errors.New("dirty")
	}
	return nil
}

// result of save discarded: the "empty path" failure is silently lost
func Persist(path string) {
	save(path)
}

// method result discarded
func Close(s *Store) {
	s.flush()
}

var closeErr = errors.New("close failed")

package families

import (
	"errors"
	"strconv"
	"strings"
)

// ---- F1 late length guard (node_exporter meminfo_numa shape)

func LateGuard(line string) (float64, error) {
	parts := strings.Fields(line)
	v, err := strconv.ParseFloat(parts[3], 64) // WANT late-guard
	if err != nil {
		return 0, err
	}
	switch len(parts) {
	case 4:
	default:
		return 0, errors.New("bad line")
	}
	return v, nil
}

func NoLateGuard(line string) string {
	parts := strings.Fields(line)
	return parts[2] // WANT plain (no length check anywhere)
}

func EarlyGuard(line string) (float64, error) {
	parts := strings.Fields(line)
	if len(parts) != 4 {
		return 0, errors.New("bad line")
	}
	return strconv.ParseFloat(parts[3], 64) // SAFE
}

// ---- F3 ignored acquire, deferred release on the same receiver (gvisor Container.Update shape)

type saver struct{ held bool }

func (s *saver) lock() error {
	if s == nil {
		return errors.New("no saver")
	}
	s.held = true
	return nil
}

func (s *saver) unlock() {
	if !s.held {
		panic("unlock without lock")
	}
	s.held = false
}

type ctr struct{ s saver }

func (c *ctr) UpdateBad() {
	c.s.lock() // WANT ignored-acquire
	defer c.s.unlock()
}

func (c *ctr) UpdateGood() error {
	if err := c.s.lock(); err != nil { // SAFE
		return err
	}
	defer c.s.unlock()
	return nil
}

// ---- F4 nil checked before err (kube-state-metrics compiledGauge.Values shape)

func get(k string) (*int, error) {
	if k == "" {
		return nil, errors.New("empty key")
	}
	if k == "none" {
		return nil, nil
	}
	v := len(k)
	return &v, nil
}

func SumBad(keys []string) (int, []error) {
	var errs []error
	total := 0
	for _, k := range keys {
		v, err := get(k) // WANT nil-before-err
		if v == nil {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		total += *v
	}
	return total, errs
}

func SumGood(keys []string) (int, []error) {
	var errs []error
	total := 0
	for _, k := range keys {
		v, err := get(k) // SAFE
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if v == nil {
			continue
		}
		total += *v
	}
	return total, errs
}

func SumNilOnly(keys []string) int {
	total := 0
	for _, k := range keys {
		v, err := get(k) // SAFE for this family (err never read: an ignored-error concern, not nil-before-err)
		_ = err
		if v == nil {
			continue
		}
		total += *v
	}
	return total
}

// ---- F6 first-separator assumption + discarded parse error (mysqld_exporter binlog shape)

func LastNumberBad(name string) float64 {
	v, _ := strconv.ParseFloat(strings.Split(name, ".")[1], 64) // WANT silent-parse
	return v
}

func LastNumberChecked(name string) (float64, error) {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return 0, errors.New("no dot")
	}
	return strconv.ParseFloat(parts[1], 64) // SAFE (guarded, error returned)
}

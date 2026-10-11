package b

type Runner struct{}

// Same names as package a, but no sink here.
func (r *Runner) Exec(v string) {}

func NewRunner() *Runner { return &Runner{} }

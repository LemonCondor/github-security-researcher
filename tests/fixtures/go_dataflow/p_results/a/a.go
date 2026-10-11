package a

type Runner struct{}

func (r *Runner) Exec(v string) { sink(v) }

func NewRunner() *Runner { return &Runner{} }

func sink(v string) {}

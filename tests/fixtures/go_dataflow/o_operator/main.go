package main

import (
	"os"
	"os/exec"

	"github.com/spf13/pflag"
)

type syncer struct {
	cmd string
}

func main() {
	flCmd := pflag.String("cmd", "git", "command to run")
	s := &syncer{cmd: *flCmd}
	s.run()
	exec.Command(os.Getenv("TOOL")).Run()
}

func (s *syncer) run() {
	exec.Command(s.cmd).Run()
}

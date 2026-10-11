package service

import "os/exec"

type Job struct {
	Script string
	Label  string
}

func Execute(j *Job) {
	exec.Command("sh", "-c", j.Script).Run()
}

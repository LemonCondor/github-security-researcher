package api

import (
	"net/http"

	"example.com/evalapp/service"
)

// TRUE command via a struct field, across files: handler -> service.Execute(&job) -> sh -c job.Script
func SubmitJob(w http.ResponseWriter, r *http.Request) {
	job := service.Job{}
	job.Script = r.FormValue("script")
	service.Execute(&job)
}

// FALSE: the controlled value is in Label, the sink reads Script (constant)
func LabelJob(w http.ResponseWriter, r *http.Request) {
	job := &service.Job{Script: "uptime"}
	job.Label = r.FormValue("label")
	service.Execute(job)
}

// FALSE: field overwritten with a constant before the call
func ResetJob(w http.ResponseWriter, r *http.Request) {
	job := service.Job{}
	job.Script = r.FormValue("script")
	job.Script = "uptime"
	service.Execute(&job)
}

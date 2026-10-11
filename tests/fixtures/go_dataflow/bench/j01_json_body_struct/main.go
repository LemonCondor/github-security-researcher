package app

import (
	"encoding/json"
	"net/http"
)

type Payload struct {
	Cmd string `json:"cmd"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	var p Payload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		return
	}
	process(p.Cmd)
}

func process(v string) {
	sink(v)
}

func sink(v string) {}

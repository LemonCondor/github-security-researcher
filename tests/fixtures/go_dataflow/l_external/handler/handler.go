package handler

import (
	extsvc "github.com/ext/service"
	st "example.org/lib/store"
)

// extsvc.Process lives outside the module: it must not be mistaken for the local service.Process.
func Handler(input string) {
	extsvc.Process(input)
}

// Abstract external sink, matched by import path through an alias.
func Store(input string) {
	st.Write(input)
}

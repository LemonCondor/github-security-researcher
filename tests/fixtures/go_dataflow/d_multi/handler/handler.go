package handler

import (
	"fmt"

	"example.com/app/service"
)

func Handler(input string) {
	fmt.Println("handling")
	service.Process(input)
}

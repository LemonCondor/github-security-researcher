package service

import repo "example.com/app/repository"

func Process(value string) {
	repo.Save("prefix:" + value)
}

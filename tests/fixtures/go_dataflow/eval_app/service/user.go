package service

import (
	"strings"

	"example.com/evalapp/repository"
)

type UserService struct {
	repo *repository.Repo
}

func (u *UserService) Lookup(name string) {
	u.repo.FindByName(strings.TrimSpace(name))
}

func (u *UserService) LookupSafe(id string) {
	u.repo.FindByID(id)
}

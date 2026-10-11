package repository

import (
	"database/sql"
	"fmt"
)

type Repo struct {
	db *sql.DB
}

func (r *Repo) FindByName(name string) {
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	r.db.Query(q)
}

func (r *Repo) FindByID(id string) {
	r.db.Query("SELECT * FROM users WHERE id = ?", id)
}

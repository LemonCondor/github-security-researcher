package api

import (
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"example.com/evalapp/service"
)

type Finder interface {
	Find(q string)
}

type Server struct {
	svc    *service.UserService
	finder Finder
	db     *sql.DB
	files  string
}

const tool = "uptime"

// TRUE sql, inter-file: handler -> helper (return) -> service -> repository -> db.Query(Sprintf)
func (s *Server) GetUser(w http.ResponseWriter, r *http.Request) {
	name := userName(r)
	s.svc.Lookup(name)
}

func userName(r *http.Request) string {
	return r.URL.Query().Get("name")
}

// FALSE sql: the value is a bound parameter
func (s *Server) GetUserSafe(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	s.svc.LookupSafe(id)
}

// TRUE command: handler -> helper -> sh -c
func RunTool(w http.ResponseWriter, r *http.Request) {
	runShell(r.FormValue("cmd"))
}

func runShell(c string) {
	exec.Command("sh", "-c", "tool "+c).Run()
}

// FALSE command: value is an argument of a fixed program, no shell
func ListBranch(w http.ResponseWriter, r *http.Request) {
	b := r.FormValue("branch")
	exec.Command("git", "branch", "--list", b).Run()
}

// FALSE command: constant program
func Uptime(w http.ResponseWriter, r *http.Request) {
	exec.Command(tool).Run()
}

// TRUE file (a controlled path reaches a file operation; traversal not established)
func (s *Server) Download(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(s.files, r.URL.Path)
	os.ReadFile(p)
}

// TRUE http: request header reaches the destination URL
func Fetch(w http.ResponseWriter, r *http.Request) {
	target := r.Header.Get("X-Target")
	http.Get("https://" + target + "/status")
}

// AMBIGUOUS: interface dispatch, implementation not determinable
func (s *Server) Search(w http.ResponseWriter, r *http.Request) {
	s.finder.Find(r.FormValue("q"))
}

// NEUTRALIZED: reassigned to a constant before the sink
func Reset(w http.ResponseWriter, r *http.Request) {
	x := r.FormValue("x")
	x = "status"
	exec.Command(x).Run()
}

// NEUTRALIZED: numeric conversion stops the flow
func (s *Server) Page(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.FormValue("page"))
	s.db.Query("SELECT * FROM t LIMIT " + strconv.Itoa(n))
}

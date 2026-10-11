package app

type Repository struct{}

type Service struct {
	repo *Repository
}

func (r *Repository) Save(v string) {
	sink(v)
}

func (s *Service) Process(v string) {
	s.repo.Save(v)
}

// Same method name on another type: must never be confused with Service.Process.
type Other struct{}

func (o *Other) Process(v string) {
	sink(v)
}

func Handler(input string) {
	s := &Service{repo: &Repository{}}
	s.Process(input)
}

func HandlerValue(input string) {
	var svc Service
	svc.Process(input)
}

func sink(v string) {}

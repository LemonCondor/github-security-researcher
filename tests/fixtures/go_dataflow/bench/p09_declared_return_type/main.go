package app

type Service struct{}

func newService() *Service { return &Service{} }

func (s *Service) Do(v string) {
	sink(v)
}

func Entry(input string) {
	s := newService()
	s.Do(input)
}

func sink(v string) {}

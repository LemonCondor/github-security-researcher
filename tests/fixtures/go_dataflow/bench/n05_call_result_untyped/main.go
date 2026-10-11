package app

type Service struct{}

func (s *Service) Do(v string) { sink(v) }

func makeAny() any { return &Service{} }

func Entry(input string) {
	s := makeAny()
	s.Do(input)
}

func sink(v string) {}

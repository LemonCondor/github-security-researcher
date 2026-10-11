package app

type Processor interface {
	Process(v string)
}

type Impl struct{}

func (Impl) Process(v string) { sink(v) }

func HandlerParam(input string, p Processor) {
	p.Process(input)
}

func HandlerVar(input string) {
	var p Processor = Impl{}
	p.Process(input)
}

func HandlerFuncValue(input string) {
	f := sink
	f(input)
}

func sink(v string) {}

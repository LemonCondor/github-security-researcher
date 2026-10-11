package app

func Reassigned(input string) {
	x := input
	x = "const"
	sink(x)
}

func BranchReassign(input string, c bool) {
	x := input
	if c {
		x = "const"
	}
	sink(x)
}

func ShadowSibling(input string, c bool) {
	x := "const"
	if c {
		x := input
		_ = x
	}
	sink(x)
}

func ShadowSame(input string) {
	x := "a"
	{
		x := input
		sink(x)
	}
	_ = x
}

func ParamKilled(input string) {
	input = "const"
	sink(input)
}

func LoopCarried(input string) {
	x := "a"
	for i := 0; i < 2; i++ {
		sink(x)
		x = input
	}
}

func PlusAssign(input string) {
	q := "a"
	q += input
	sink(q)
}

func IfInit(input string) {
	if v := input; v != "" {
		sink(v)
	}
}

func Range(inputs []string) {
	for _, v := range inputs {
		sink(v)
	}
}

func RangeIndex(inputs []string) {
	for i := range inputs {
		sinkInt(i)
	}
}

func Helper(input string) {
	sink(wrap(input))
}

func wrap(s string) string { return "[" + s + "]" }

func Multi(input string) {
	a, err := split(input)
	_ = err
	sink(a)
}

func MultiOther(input string) {
	_, e := split(input)
	sink(e)
}

func split(s string) (string, string) { return s, "" }

func sink(v string) {}

func sinkInt(i int) {}

type Node struct{}

func (n *Node) Next() (*Node, error) { return n, nil }

// Receiver type defined in terms of itself: must not recurse forever.
func SelfReferential(input string) {
	n := &Node{}
	n, _ = n.Next()
	n.Next()
	sink(input)
}

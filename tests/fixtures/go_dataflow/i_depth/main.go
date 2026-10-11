package app

func A(x string) { B(x) }
func B(x string) { C(x) }
func C(x string) { D(x) }
func D(x string) { E(x) }
func E(x string) { F(x) }
func F(x string) { sink(x) }

func sink(v string) {}

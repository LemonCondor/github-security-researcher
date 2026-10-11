package app

func Entry(input string) { h1(input) }

func h1(v string) { h2(v) }

func h2(v string) { h3(v) }

func h3(v string) { h4(v) }

func h4(v string) { sink(v) }

func sink(v string) {}

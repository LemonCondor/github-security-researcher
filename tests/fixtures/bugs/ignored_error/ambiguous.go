package app

// explicit discard: may be deliberate
func PersistBestEffort(path string) {
	_ = save(path)
}

// deferred call: common idiom, intent unknown
func PersistDeferred(path string) {
	defer save(path)
}

type Conn struct{}

func (c *Conn) Close() error { return closeErr }

// teardown: errors of Close are often deliberately best-effort
func Shutdown(c *Conn) {
	c.Close()
}

package gorcon

type RCONServerConfigFlags int
type RCONServerConfig struct {
	Flags RCONServerConfigFlags
}

const (
	CommandInGoroutine RCONServerConfigFlags = 1 << iota
)

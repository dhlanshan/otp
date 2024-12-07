package abstract

type Key interface {
}

type Otp interface {
	GenerateCode(counters ...any) ([]string, error)
	Validate(passCode string, counters ...any) (bool, error)
	GenerateKey() (string, error)
}

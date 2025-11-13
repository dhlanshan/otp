package abstract

type Key interface {
}

type Otp interface {
	GenerateCode(args any) ([]string, error)
	Validate(passCode string, args any) (bool, error)
	GenerateKey() (string, error)
}

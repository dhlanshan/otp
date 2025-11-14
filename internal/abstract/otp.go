package abstract

type Otp interface {
	GenerateCode(args any) ([]string, error)
	Validate(passCode string, args any) bool
	GenerateKey(args any) (string, error)
}

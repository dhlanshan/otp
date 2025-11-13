package abstract

import "github.com/dhlanshan/otp/core"

type Pattern interface {
	GenCounter(internalArg *core.InternalArg, args any) ([]byte, error)
	Calculation(internalArg *core.InternalArg, hash []byte, args any) (string, error)
}

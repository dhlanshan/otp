package abstract

import (
	"github.com/dhlanshan/otp/dto"
)

type Pattern interface {
	GenCounter(internalArg *dto.InternalArg, args any) ([]byte, error)
	Calculation(internalArg *dto.InternalArg, hash []byte, args any) (string, error)
	GenUrl(internalArg *dto.InternalArg, args any) (string, error)
}

package realize

import (
	"encoding/binary"
	"github.com/dhlanshan/otp/core"
	"github.com/dhlanshan/otp/truncate"
	"math"
)

type StandardArg struct {
	Skew   uint
	Secret []byte
}

type StandardPattern struct{}

func (sp *StandardPattern) GenCounter(internalArg *core.InternalArg, args any) ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, internalArg.Counter)

	return buf, nil
}

func (sp *StandardPattern) Calculation(internalArg *core.InternalArg, hash []byte, args any) (string, error) {
	trc, err := truncate.StandardTruncate(hash)
	if err != nil {
		return "", err
	}
	dl := internalArg.Digits.Length()
	mod := trc % int64(math.Pow10(dl))

	return internalArg.Digits.Format(int32(mod)), nil
}

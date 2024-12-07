package abstract

import "github.com/dhlanshan/otp/internal/enum"

type Pattern interface {
	CounterFun(buf []byte, str ...string) ([]byte, error)
	CalculationFun(value int64, dl int, digits enum.DigitEnum) string
}

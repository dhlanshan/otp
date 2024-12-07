package realize

import (
	"errors"
	"github.com/dhlanshan/otp/enum"
	"math"
)

// StandardPattern hotp|totp
type StandardPattern struct{}

func (hp *StandardPattern) CounterFun(buf []byte, str ...string) ([]byte, error) {
	return buf, nil
}

func (hp *StandardPattern) CalculationFun(value int64, dl int, digits enum.DigitEnum) string {
	mod := value % int64(math.Pow10(dl))
	return digits.Format(int32(mod))
}

// SteamPattern steam
type SteamPattern struct{}

func (sp *SteamPattern) CounterFun(buf []byte, str ...string) ([]byte, error) {
	return buf, nil
}

func (sp *SteamPattern) CalculationFun(value int64, dl int, digits enum.DigitEnum) string {
	result := ""
	steamChars := "23456789BCDFGHJKMNPQRTVWXY"
	sl := int64(len(steamChars))
	for i := 0; i < dl; i++ {
		result += string(steamChars[value%sl])
		value /= sl
	}

	return result
}

// MobilePattern mobile
type MobilePattern struct{}

func (mp *MobilePattern) CounterFun(buf []byte, str ...string) ([]byte, error) {
	if len(str) == 0 {
		return nil, errors.New("in mobile mode, the PIN cannot be empty")
	}
	buf = append([]byte(str[0]), buf...)

	return buf, nil
}

func (mp *MobilePattern) CalculationFun(value int64, dl int, digits enum.DigitEnum) string {
	result := ""
	charSet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	sl := int64(len(charSet))
	for i := 0; i < dl; i++ {
		result = string(charSet[value%sl]) + result
		value /= sl
	}

	return result
}

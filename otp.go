package otp

import (
	"encoding/json"
	"errors"
	"github.com/dhlanshan/otp/hotp"
	"github.com/dhlanshan/otp/internal/abstract"
	"github.com/dhlanshan/otp/internal/command"
	"github.com/dhlanshan/otp/totp"
	"strings"
)

func NewOtpInstance(cmd *CreateOtpCmd) (abstract.Otp, error) {
	var newCmd *command.CreateOtpCmd
	n, _ := json.Marshal(cmd)
	_ = json.Unmarshal(n, &newCmd)
	switch cmd.OtpType {
	case HOTP:
		return hotp.NewHOtp(newCmd)
	case TOTP:
		return totp.NewTOtp(newCmd)
	default:
		return nil, errors.New("unsupported OTP type")
	}
}

// GenerateKey generate token KEY address
func GenerateKey(cmd *CreateOtpCmd) (string, error) {
	obj, err := NewOtpInstance(cmd)
	if err != nil {
		return "", err
	}

	k, err := obj.GenerateKey()

	return k, err
}

// GenerateCode generate dynamic password
func GenerateCode(cmd *CreateOtpCmd, counters ...any) (string, error) {
	obj, err := NewOtpInstance(cmd)
	if err != nil {
		return "", err
	}

	code, err := obj.GenerateCode(counters...)

	return strings.Join(code, ""), err
}

// Validate verify dynamic code
func Validate(cmd *CreateOtpCmd, passCode string, counters ...any) bool {
	obj, err := NewOtpInstance(cmd)
	if err != nil {
		return false
	}
	res, _ := obj.Validate(passCode, counters...)

	return res
}

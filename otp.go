package otp

import (
	"errors"
	"github.com/dhlanshan/otp/core"
	"github.com/dhlanshan/otp/dto"
	"github.com/dhlanshan/otp/enum"
	"github.com/dhlanshan/otp/internal/abstract"
	"github.com/dhlanshan/otp/internal/util"
	"strings"
)

func NewOtp(cmd dto.CreateOtpCmd) (abstract.Otp, error) {
	switch cmd.OtpType {
	case enum.HOTP:
		return core.NewHOtp(cmd)
	case enum.TOTP:
		return core.NewTOtp(cmd)
	default:
		return nil, errors.New("unsupported OTP type")
	}
}

// GenUrl 生成URL
func GenUrl(obj abstract.Otp, args any) (string, error) {
	return obj.GenerateKey(args)
}

// GenCode generate dynamic password
func GenCode(obj abstract.Otp, args any) (string, error) {
	code, err := obj.GenerateCode(args)
	return strings.Join(code, ""), err
}

// Validate verify dynamic code
func Validate(obj abstract.Otp, passCode string, args any) bool {
	return obj.Validate(passCode, args)
}

func SecretToEncSecret(secret string) string {
	return core.B32NoPadding.EncodeToString([]byte(secret))
}

func EncSecretToSecret(encSecret string) (string, error) {
	a, err := util.DecodeBase32Secret(encSecret)
	if err != nil {
		return "", err
	}
	return string(a), nil
}

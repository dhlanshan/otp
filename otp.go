package otp

import (
	"encoding/json"
	"errors"
	"github.com/dhlanshan/otp/hotp"
	"github.com/dhlanshan/otp/internal/abstract"
	"github.com/dhlanshan/otp/internal/command"
	"github.com/dhlanshan/otp/internal/common"
	"github.com/dhlanshan/otp/internal/util"
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
func GenerateKey(obj *abstract.Otp) (string, error) {
	obj, err := NewOtpInstance(cmd)
	if err != nil {
		return "", err
	}

	k, err := obj.GenerateKey()

	return k, err
}

// GenerateCode generate dynamic password
func GenerateCode(obj abstract.Otp, args any) (string, error) {
	code, err := obj.GenerateCode(args)
	return strings.Join(code, ""), err
}

// Validate verify dynamic code
func Validate(obj abstract.Otp, passCode string, args any) bool {
	res, _ := obj.Validate(passCode, args)

	return res
}

func SecretToEncSecret(secret string) string {
	return common.B32NoPadding.EncodeToString([]byte(secret))
}

func EncSecretToSecret(encSecret string) (string, error) {
	a, err := util.DecodeBase32Secret(encSecret)
	if err != nil {
		return "", err
	}
	return string(a), nil
}

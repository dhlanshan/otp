package otp

import (
	"encoding/json"
	"errors"
	"github.com/dhlanshan/otp/hotp"
	"github.com/dhlanshan/otp/internal/command"
	"github.com/dhlanshan/otp/internal/common"
	"github.com/dhlanshan/otp/totp"
	"strings"
)

func newOtpInstance(cmd *CreateOtpCmd) (common.AbstractOtp, error) {
	var newCmd *command.CreateOtpCmd
	n, _ := json.Marshal(cmd)
	_ = json.Unmarshal(n, &newCmd)
	switch cmd.OtpType {
	case HOTP:
		return hotp.NewHOtp(newCmd)
	case TOTP:
		return totp.NewTOtp(newCmd)
	default:
		return nil, errors.New("不支持的OTP类型")
	}
}

// GenerateKey 生成令牌器
func GenerateKey(cmd *CreateOtpCmd) (string, error) {
	obj, err := newOtpInstance(cmd)
	if err != nil {
		return "", err
	}
	// 生成秘钥
	k, err := obj.GenerateKey()
	if err != nil {
		return "", err
	}

	return k.Url.String(), nil
}

// GenerateCode 生成动态密码
func GenerateCode(cmd *CreateOtpCmd, counters ...uint64) (string, error) {
	obj, err := newOtpInstance(cmd)
	if err != nil {
		return "", err
	}
	// 生成秘钥
	code, err := obj.GenerateCode(counters...)

	return strings.Join(code, ""), err
}

// Validate 校验动态码
func Validate(cmd *CreateOtpCmd, passCode string, counters ...uint64) bool {
	obj, err := newOtpInstance(cmd)
	if err != nil {
		return false
	}
	res, _ := obj.Validate(passCode, counters...)

	return res
}

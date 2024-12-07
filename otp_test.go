package otp

import (
	"errors"
	"fmt"
	"github.com/dhlanshan/otp/enum"
	"github.com/dhlanshan/otp/internal/common"
	"testing"
)

func TestGenerateKeyByHOtp(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: HOTP, Secret: "dhlanshan"}
	key, err := GenerateKey(cmd)
	fmt.Println(key, err)
}

func TestGenerateCodeByHOtp(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: HOTP, Secret: "dhlanshan"}
	code, err := GenerateCode(cmd, uint64(2))
	fmt.Println(code, err)
}

func TestValidateByHOtp(t *testing.T) {
	passCode := "358324"
	cmd := &CreateOtpCmd{OtpType: HOTP, EncSecret: "MRUGYYLOONUGC3Q"}
	res := Validate(cmd, passCode, uint64(3))
	fmt.Println(res)
}

func TestGenerateKeyByTOtp(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan"}
	key, err := GenerateKey(cmd)
	fmt.Println(key, err)
}

func TestGenerateCodeByTOtp(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan"}
	code, err := GenerateCode(cmd)
	fmt.Println(code, err)
}

func TestValidateByTOtp(t *testing.T) {
	passCode := "585641"
	cmd := &CreateOtpCmd{OtpType: TOTP, EncSecret: "MRUGYYLOONUGC3Q", Skew: 1}
	res := Validate(cmd, passCode)
	fmt.Println(res)
}

func TestGenerateKeyBySteam(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Pattern: enum.Steam}
	key, err := GenerateKey(cmd)
	fmt.Println(key, err)
}

func TestGenerateCodeBySteam(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Pattern: enum.Steam}
	code, err := GenerateCode(cmd)
	fmt.Println(code, err)
}

func TestValidateBySteam(t *testing.T) {
	passCode := "47M6M"
	cmd := &CreateOtpCmd{OtpType: TOTP, EncSecret: "MRUGYYLOONUGC3Q", Pattern: enum.Steam, Skew: 1}
	res := Validate(cmd, passCode)
	fmt.Println(res)
}

func TestGenerateKeyByMobile(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Pattern: enum.Mobile}
	key, err := GenerateKey(cmd)
	fmt.Println(key, err)
}

// MobilePattern Mobile模式
type MobilePattern struct{}

func (mp *MobilePattern) CounterFun(buf []byte, str ...string) ([]byte, error) {
	if len(str) == 0 {
		return nil, errors.New("mobile模式下, pin不能为空")
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

func TestGenerateCodeByMobile(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Pattern: enum.Mobile, Period: 30}
	common.PatternMap["mobile"] = &MobilePattern{}
	code, err := GenerateCode(cmd, "6688")
	fmt.Println(code, err)
}

func TestValidateByMobile(t *testing.T) {
	passCode := "bAiuCX"
	common.PatternMap["mobile"] = &MobilePattern{}
	cmd := &CreateOtpCmd{OtpType: TOTP, EncSecret: "MRUGYYLOONUGC3Q", Pattern: enum.Mobile, Period: 30}
	res := Validate(cmd, passCode, "6688")
	fmt.Println(res)
}

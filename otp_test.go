package otp

import (
	"fmt"
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
	passCode := "303087"
	cmd := &CreateOtpCmd{OtpType: TOTP, EncSecret: "MRUGYYLOONUGC3Q", Skew: 1}
	res := Validate(cmd, passCode)
	fmt.Println(res)
}

func TestGenerateKeyBySteam(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Pattern: Steam}
	key, err := GenerateKey(cmd)
	fmt.Println(key, err)
}

func TestGenerateCodeBySteam(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Pattern: Steam}
	code, err := GenerateCode(cmd)
	fmt.Println(code, err)
}

func TestValidateBySteam(t *testing.T) {
	passCode := "V6NRM"
	cmd := &CreateOtpCmd{OtpType: TOTP, EncSecret: "MRUGYYLOONUGC3Q", Pattern: Steam, Skew: 1}
	res := Validate(cmd, passCode)
	fmt.Println(res)
}

func TestGenerateKeyByMobile(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Pattern: Mobile}
	key, err := GenerateKey(cmd)
	fmt.Println(key, err)
}

func TestGenerateCodeByMobile(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Pattern: Mobile, Period: 1}
	code, err := GenerateCode(cmd, "6688")
	fmt.Println(code, err)
}

func TestValidateByMobile(t *testing.T) {
	passCode := "GRTG2"
	cmd := &CreateOtpCmd{OtpType: TOTP, EncSecret: "MRUGYYLOONUGC3Q", Pattern: Mobile}
	res := Validate(cmd, passCode)
	fmt.Println(res)
}

package otp

import (
	"fmt"
	"testing"
)

func TestGenerateKeyByHOtp(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: HOTP, Secret: "dhlanshan"}
	key, err := GenerateKey(cmd)
	fmt.Println(key, err)
	// otpauth://hotp/%E7%81%AF%E7%81%AB%E9%98%91%E7%8F%8A:bee?algorithm=SHA1&digits=6&issuer=%E7%81%AF%E7%81%AB%E9%98%91%E7%8F%8A&secret=MRUGYYLOONUGC3Q
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
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Digits: 8}
	key, err := GenerateKey(cmd)
	fmt.Println(key, err)
}

func TestGenerateCodeByTOtp(t *testing.T) {
	cmd := &CreateOtpCmd{OtpType: TOTP, Secret: "dhlanshan", Digits: 8}
	code, err := GenerateCode(cmd)
	fmt.Println(code, err)
}

func TestValidateByTOtp(t *testing.T) {
	passCode := "45609279"
	cmd := &CreateOtpCmd{OtpType: TOTP, EncSecret: "MRUGYYLOONUGC3Q", Digits: 8, Skew: 1}
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
	passCode := "GRTG2"
	cmd := &CreateOtpCmd{OtpType: TOTP, EncSecret: "MRUGYYLOONUGC3Q", Pattern: Steam}
	res := Validate(cmd, passCode)
	fmt.Println(res)
}

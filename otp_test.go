package otp

import (
	"fmt"
	"github.com/dhlanshan/otp/dto"
	"github.com/dhlanshan/otp/enum"
	"testing"
)

func TestTotpGenCodeByStandard(t *testing.T) {
	otp, err := NewOtp(dto.CreateOtpCmd{Issuer: "哈哈哈", OtpType: enum.TOTP, Secret: "WAuQWuPjVoTRprcqp7hv", Pattern: enum.Standard})
	if err != nil {
		t.Error(err)
	}
	args := &dto.StandardArg{}
	key, err := GenCode(otp, args)
	fmt.Println(key, err)
}

func TestTotpValidateByStandard(t *testing.T) {
	otp, err := NewOtp(dto.CreateOtpCmd{Issuer: "哈哈哈", OtpType: enum.TOTP, Secret: "WAuQWuPjVoTRprcqp7hv", Pattern: enum.Standard})
	if err != nil {
		t.Error(err)
	}
	args := &dto.StandardArg{}
	passCode := "661997"
	result := Validate(otp, passCode, args)
	fmt.Println(result)
}

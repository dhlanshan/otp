package dto

import "github.com/dhlanshan/otp/enum"

type InternalArg struct {
	Issuer     string
	Skew       uint
	SecretSize uint
	Secret     []byte
	EncSecret  string
	Period     uint
	Digits     enum.DigitEnum
	Algorithm  enum.AlgorithmEnum
	Pattern    enum.PatternEnum

	OtpType     enum.OtpTypeEnum // otp类型
	TimeCounter uint64           // 时间计数
}

type StandardArg struct {
	Counter     uint64
	Skew        uint
	Secret      []byte
	AccountName string
}

package core

import "github.com/dhlanshan/otp/enum"

type InternalArg struct {
	Counter uint64 // 计数
	Digits  enum.DigitEnum
}

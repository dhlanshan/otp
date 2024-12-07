package otp

import (
	"github.com/dhlanshan/otp/enum"
	"github.com/dhlanshan/otp/internal/abstract"
	"github.com/dhlanshan/otp/internal/common"
)

type TypeEnum string

const (
	HOTP TypeEnum = "hotp"
	TOTP TypeEnum = "totp"
)

// CreateOtpCmd OTP参数
type CreateOtpCmd struct {
	Issuer      string             // 发证机构/公司的名称
	AccountName string             // 用户帐户名称（如电子邮件地址
	OtpType     TypeEnum           // otp类型
	Period      uint               // TOTP哈希有效的秒数。默认为30秒
	Skew        uint               // 允许的当前时间之前或之后的时段。值为1时，最多允许指定时间两侧的Period。默认为0
	SecretSize  uint               // 生成的秘钥的大小。默认为20字节。当秘钥需要随机生成时使用该字段
	Secret      string             // 存储的秘钥。默认为随机生成的SecretSize秘钥
	EncSecret   string             // 编码后的秘钥
	Digits      int                // 密码位数
	Algorithm   enum.AlgorithmEnum // 用于HMAC的算法。默认为SHA1
	Pattern     enum.PatternEnum   // 模式
	Host        string             // host
}

type Aop struct {
	PatternName enum.PatternEnum // 模式名
	Pattern     abstract.Pattern
}

func AddOtpPattern(ps []Aop) {
	for _, p := range ps {
		common.PatternMap[p.PatternName] = p.Pattern
	}
}

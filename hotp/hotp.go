package hotp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/dhlanshan/otp/internal/command"
	"github.com/dhlanshan/otp/internal/common"
	"io"
	"math"
	"net/url"
	"strings"
)

type HOtp struct {
	Issuer      string               // 发证机构/公司的名称
	AccountName string               // 用户账户名称(如电子邮件地址)
	SecretSize  uint                 // 生成的秘钥的大小。默认为20字节。当秘钥需要随机生成时使用该字段
	Secret      []byte               // 原始秘钥。默认为随机生成的SecretSize秘钥
	EncSecret   string               // 编码后的秘钥
	Digits      common.DigitEnum     // 密码位数
	Algorithm   common.AlgorithmEnum // 用于HMAC的算法。默认为SHA1
	Pattern     common.PatternEnum   // 模式
	Rand        io.Reader            // 用于生成TOTP密钥的读卡器
}

// NewHOtp 创建一个新的 HOtp 实例
func NewHOtp(cmd *command.CreateOtpCmd) (*HOtp, error) {
	hObj := &HOtp{
		Issuer:      cmd.Issuer,
		AccountName: cmd.AccountName,
		SecretSize:  cmd.SecretSize,
		Secret:      []byte(cmd.Secret),
		EncSecret:   cmd.EncSecret,
		Digits:      cmd.Digits,
		Algorithm:   cmd.Algorithm,
		Pattern:     cmd.Pattern,
		Rand:        rand.Reader, // 默认为安全的随机数生成器
	}
	if err := hObj.Init(); err != nil {
		return nil, errors.New(fmt.Sprintf("HOTP 初始化失败: %s", err.Error()))
	}

	return hObj, nil
}

func (h *HOtp) Init() error {
	if h.Issuer == "" {
		h.Issuer = common.DefaultIssuer
	}
	if h.AccountName == "" {
		h.AccountName = common.DefaultAccountName
	}
	if h.SecretSize == 0 {
		h.SecretSize = common.DefaultSecretSize
	}
	if h.Digits == 0 {
		h.Digits = common.DigitSix
	}
	if h.Rand == nil {
		h.Rand = rand.Reader
	}
	if h.EncSecret != "" {
		secret, err := common.DecodeBase32Secret(h.EncSecret)
		if err != nil {
			return errors.New("秘钥解码失败")
		}
		h.Secret = secret
		h.SecretSize = uint(len(secret))
	}
	if len(h.Secret) == 0 {
		h.Secret = make([]byte, h.SecretSize)
		if _, err := h.Rand.Read(h.Secret); err != nil {
			return errors.New("初始化秘钥错误。")
		}
	} else {
		h.SecretSize = uint(len(h.Secret))
	}
	if h.EncSecret == "" {
		h.EncSecret = common.B32NoPadding.EncodeToString(h.Secret)
	}

	return nil
}

func (h *HOtp) GenerateCodeForCounter(counter uint64) (passCode string, err error) {
	if h.Digits == 0 {
		return "", errors.New("密码位数错误")
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(h.Algorithm.Hash, h.Secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	dl := h.Digits.Length()
	switch h.Pattern {
	case common.Standard:
		mod := value % int64(math.Pow10(dl))
		passCode = h.Digits.Format(int32(mod))
	case common.Steam:
		steamChars := "23456789BCDFGHJKMNPQRTVWXY"
		sl := int64(len(steamChars))
		for i := 0; i < dl; i++ {
			passCode += string(steamChars[value%sl])
			value /= sl
		}
	}

	return
}

func (h *HOtp) ValidateForCounter(passCode string, counter uint64) (bool, error) {
	passCode = strings.TrimSpace(passCode)
	if len(passCode) != h.Digits.Length() {
		return false, errors.New("密码位数错误")
	}

	newPassCode, err := h.GenerateCodeForCounter(counter)
	if err != nil {
		return false, err
	}

	if !(subtle.ConstantTimeCompare([]byte(newPassCode), []byte(passCode)) == 1) {
		return false, nil
	}

	return true, nil
}

// GenerateCode 生成动态密码
func (h *HOtp) GenerateCode(counters ...uint64) ([]string, error) {
	if len(counters) == 0 {
		return nil, errors.New("counters is empty")
	}

	passCode, err := h.GenerateCodeForCounter(counters[0])
	if err != nil {
		return nil, err
	}

	return []string{passCode}, nil
}

// Validate 校验动态密码
func (h *HOtp) Validate(passCode string, counters ...uint64) (bool, error) {
	if len(counters) == 0 {
		return false, errors.New("counters is empty")
	}

	return h.ValidateForCounter(passCode, counters[0])
}

// GenerateKey 生成新key
func (h *HOtp) GenerateKey() (*common.Key, error) {
	if h.Issuer == "" || h.AccountName == "" {
		return nil, errors.New("缺少必要的账户信息")
	}

	val := url.Values{}
	val.Set("secret", h.EncSecret)
	val.Set("issuer", h.Issuer)
	val.Set("algorithm", h.Algorithm.String())
	val.Set("digits", h.Digits.String())

	u := url.URL{Scheme: "otpauth", Host: "hotp", Path: "/" + h.Issuer + ":" + h.AccountName, RawQuery: common.EncodeQuery(val)}

	return common.NewKeyFromURL(u.String())
}

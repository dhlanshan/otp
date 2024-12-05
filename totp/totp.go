package totp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/dhlanshan/otp/hotp"
	"github.com/dhlanshan/otp/internal/command"
	"github.com/dhlanshan/otp/internal/common"
	"io"
	"math"
	"net/url"
	"strconv"
	"time"
)

type TOtp struct {
	Issuer      string               // 发证机构/公司的名称
	AccountName string               // 用户帐户名称（如电子邮件地址）
	Period      uint                 // TOTP哈希有效的秒数。默认为30秒
	Skew        uint                 // 允许的当前时间之前或之后的时段。值为1时，最多允许指定时间两侧的Period。默认为0。大于1的值可能是粗略的
	SecretSize  uint                 // 生成的秘钥的大小。默认为20字节。当秘钥需要随机生成时使用该字段
	Secret      []byte               // 存储的秘钥。默认为随机生成的SecretSize秘钥
	EncSecret   string               // 编码后的秘钥
	Digits      common.DigitEnum     // 动态密码位数
	Algorithm   common.AlgorithmEnum // 用于HMAC的算法。默认为SHA1
	Pattern     common.PatternEnum   // 模式
	Rand        io.Reader            // 随机数生成器
}

func NewTOtp(cmd *command.CreateOtpCmd) (*TOtp, error) {
	tObj := &TOtp{
		Issuer:      cmd.Issuer,
		AccountName: cmd.AccountName,
		Period:      cmd.Period,
		Skew:        cmd.Skew,
		SecretSize:  cmd.SecretSize,
		Secret:      []byte(cmd.Secret),
		EncSecret:   cmd.EncSecret,
		Digits:      cmd.Digits,
		Algorithm:   cmd.Algorithm,
		Pattern:     cmd.Pattern,
		Rand:        rand.Reader,
	}
	if err := tObj.Init(); err != nil {
		return nil, errors.New(fmt.Sprintf("TOTP 初始化失败: %s", err.Error()))
	}

	return tObj, nil
}

func (t *TOtp) Init() error {
	if t.Issuer == "" {
		t.Issuer = common.DefaultIssuer
	}
	if t.AccountName == "" {
		t.AccountName = common.DefaultAccountName
	}
	if t.Period == 0 {
		t.Period = common.DefaultPeriod
	}
	if t.SecretSize == 0 {
		t.SecretSize = common.DefaultSecretSize
	}
	if t.Digits == 0 {
		t.Digits = common.DigitSix
	}
	if t.Rand == nil {
		t.Rand = rand.Reader
	}
	if t.EncSecret != "" {
		secret, err := common.DecodeBase32Secret(t.EncSecret)
		if err != nil {
			return errors.New("秘钥解码失败")
		}
		t.Secret = secret
		t.SecretSize = uint(len(secret))
	}
	if len(t.Secret) == 0 {
		t.Secret = make([]byte, t.SecretSize)
		if _, err := t.Rand.Read(t.Secret); err != nil {
			return errors.New("初始化秘钥错误。")
		}
	} else {
		t.SecretSize = uint(len(t.Secret))
	}
	if t.EncSecret == "" {
		t.EncSecret = common.B32NoPadding.EncodeToString(t.Secret)
	}
	if t.Pattern == common.Steam {
		t.Digits = 5
		t.Period = 30
		t.Algorithm = common.AlgorithmSHA1
	}

	return nil
}

// GenerateCode 生成动态密码
func (t *TOtp) GenerateCode(counters ...any) ([]string, error) {
	nowTime := time.Now().UTC()
	counter := int64(math.Floor(float64(nowTime.Unix()) / float64(t.Period)))

	// 根据类型拆分counters
	_, pin := common.ParameterParsing(t.Pattern, counters)
	if t.Pattern == common.Mobile && pin == "" {
		return nil, errors.New("缺少pin参数")
	}

	newCounters := common.CalculateCounters(counter, t.Skew)
	hOpt := hotp.HOtp{Digits: t.Digits, Algorithm: t.Algorithm, Secret: t.Secret, Pattern: t.Pattern, Rand: t.Rand}

	passCodes := make([]string, 0, len(newCounters))
	for _, c := range newCounters {
		passCode, err := hOpt.GenerateCodeForCounter(c, pin)
		if err != nil {
			return nil, fmt.Errorf("生成动态码失败: %w", err)
		}
		passCodes = append(passCodes, passCode)
	}
	return passCodes, nil
}

func (t *TOtp) getHost() string {
	host := "totp"
	switch t.Pattern {
	case common.Steam:
		host = "steam"
	case common.Mobile:
		host = "motp"
	}

	return host
}

// Validate 校验动态密码
func (t *TOtp) Validate(passCode string, counters ...any) (bool, error) {
	nowTime := time.Now().UTC()
	counter := int64(math.Floor(float64(nowTime.Unix()) / float64(t.Period)))

	// 根据类型拆分counters
	_, pin := common.ParameterParsing(t.Pattern, counters)
	if t.Pattern == common.Mobile && pin == "" {
		return false, errors.New("缺少pin参数")
	}

	newCounters := common.CalculateCounters(counter, t.Skew)
	hObj := hotp.HOtp{Digits: t.Digits, Algorithm: t.Algorithm, Secret: t.Secret, Pattern: t.Pattern}

	for _, c := range newCounters {
		isValid, err := hObj.ValidateForCounter(passCode, c, pin)
		if err != nil {
			return false, fmt.Errorf("校验失败: %w", err)
		}
		if isValid {
			return true, nil
		}
	}
	return false, errors.New("动态码无效")
}

// GenerateKey 生成key
func (t *TOtp) GenerateKey() (*common.Key, error) {
	if t.Issuer == "" || t.AccountName == "" {
		return nil, errors.New("缺少必要的账户信息")
	}

	val := url.Values{}
	val.Set("secret", t.EncSecret)
	val.Set("issuer", t.Issuer)
	val.Set("period", strconv.FormatUint(uint64(t.Period), 10))
	val.Set("algorithm", t.Algorithm.String())
	val.Set("digits", t.Digits.String())

	u := url.URL{Scheme: "otpauth", Host: t.getHost(), Path: "/" + url.PathEscape(t.Issuer+":"+t.AccountName), RawQuery: common.EncodeQuery(val)}

	return common.NewKeyFromURL(u.String())
}

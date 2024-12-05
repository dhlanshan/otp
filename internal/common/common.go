package common

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"net/url"
	"sort"
	"strings"
)

type AbstractOtp interface {
	GenerateCode(counters ...any) ([]string, error)
	Validate(passCode string, counters ...any) (bool, error)
	GenerateKey() (*Key, error)
}

// 默认配置
const (
	DefaultIssuer      = "灯火阑珊"
	DefaultAccountName = "bee"
	DefaultPeriod      = 30
	DefaultSecretSize  = 20
)

// PatternEnum 模式
type PatternEnum string

const (
	Standard PatternEnum = ""       // 标准模式
	Steam    PatternEnum = "steam"  // Steam模式
	Mobile   PatternEnum = "mobile" // Mobile模式
)

// AlgorithmEnum 算法
type AlgorithmEnum int

const (
	AlgorithmSHA1 AlgorithmEnum = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

func (a AlgorithmEnum) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}
	panic("unreached")
}

func (a AlgorithmEnum) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}
	panic("unreached")
}

// DigitEnum 密码长度
type DigitEnum int

const (
	DigitFour  DigitEnum = 4
	DigitSix   DigitEnum = 6
	DigitEight DigitEnum = 8
)

// Format converts an integer into the zero-filled size for this Digits.
func (d DigitEnum) Format(in int32) string {
	f := fmt.Sprintf("%%0%dd", d)
	return fmt.Sprintf(f, in)
}

// Length returns the number of characters for this Digits.
func (d DigitEnum) Length() int {
	return int(d)
}

func (d DigitEnum) String() string {
	return fmt.Sprintf("%d", d)
}

type Key struct {
	Orig string
	Url  *url.URL
}

func NewKeyFromURL(orig string) (*Key, error) {
	s := strings.TrimSpace(orig)

	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return &Key{
		Orig: s,
		Url:  u,
	}, nil
}

var B32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

func EncodeQuery(v url.Values) string {
	if v == nil {
		return ""
	}
	var buf strings.Builder
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := v[k]
		keyEscaped := url.PathEscape(k)
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(keyEscaped)
			buf.WriteByte('=')
			buf.WriteString(url.PathEscape(v))
		}
	}
	return buf.String()
}

// DecodeBase32Secret 解码 Base32 秘钥
func DecodeBase32Secret(encSecret string) ([]byte, error) {
	encSecret = strings.ToUpper(strings.TrimSpace(encSecret))
	if n := len(encSecret) % 8; n != 0 {
		encSecret += strings.Repeat("=", 8-n)
	}
	return base32.StdEncoding.DecodeString(encSecret)
}

// CalculateCounters 计算时间偏移窗口内的所有计数器值
func CalculateCounters(baseCounter int64, skew uint) []uint64 {
	counters := []uint64{uint64(baseCounter)}
	for i := 1; i <= int(skew); i++ {
		counters = append(counters, uint64(baseCounter+int64(i)))
		counters = append(counters, uint64(baseCounter-int64(i)))
	}
	return counters
}

// ParameterParsing 参数解析
func ParameterParsing(pattern PatternEnum, counters ...any) (counter uint64, pin string) {
	switch pattern {
	case Mobile:
		cc := counters[0].([]any)
		for i, c := range cc {
			if i >= 2 {
				continue
			}
			switch v := c.(type) {
			case string:
				if pin == "" {
					pin = v
				}
			case uint64:
				if counter == 0 {
					counter = v
				}
			}
		}
	default:
		if nested, ok := counters[0].([]any); ok && len(nested) > 0 {
			if v, ok := nested[0].(uint64); ok && v != 0 {
				counter = v
			}
		}
	}

	return
}

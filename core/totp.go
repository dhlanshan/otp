package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"github.com/dhlanshan/otp/dto"
	"github.com/dhlanshan/otp/enum"
	"github.com/dhlanshan/otp/infrastructure"
	"github.com/dhlanshan/otp/internal/util"
	"io"
	"math"
	"strings"
	"time"
)

type TOtp struct {
	Issuer string

	Skew       uint
	SecretSize uint
	Secret     []byte
	EncSecret  string

	Period    uint
	Digits    enum.DigitEnum
	Algorithm enum.AlgorithmEnum
	Pattern   enum.PatternEnum
	rand      io.Reader
}

// NewTOtp initializes and returns a new TOtp instance based on the provided CreateOtpCmd configuration.
func NewTOtp(cmd dto.CreateOtpCmd) (*TOtp, error) {
	tObj := &TOtp{
		Issuer:     cmd.Issuer,
		Skew:       cmd.Skew,
		SecretSize: cmd.SecretSize,
		Secret:     []byte(cmd.Secret),
		EncSecret:  cmd.EncSecret,
		Period:     cmd.Period,
		Digits:     cmd.Digits,
		Algorithm:  cmd.Algorithm,
		Pattern:    cmd.Pattern,
		rand:       rand.Reader,
	}
	if err := tObj.Init(); err != nil {
		return nil, fmt.Errorf("TOTP init failed: %w", err)
	}

	return tObj, nil
}

func (t *TOtp) Init() error {
	t.Period = util.Ternary(t.Period == 0, DefaultPeriod, t.Period)
	t.SecretSize = util.Ternary(t.SecretSize == 0, DefaultSecretSize, t.SecretSize)
	t.Digits = util.Ternary(t.Digits == 0, enum.DigitSix, t.Digits)
	if util.RemoveAllSpace(t.EncSecret) != "" {
		secret, err := util.DecodeBase32Secret(t.EncSecret)
		if err != nil {
			return fmt.Errorf("encSecret decode failed: %w", err)
		}
		t.Secret = secret
		t.SecretSize = uint(len(secret))
	}
	if util.RemoveAllSpace(string(t.Secret)) == "" {
		t.Secret = make([]byte, t.SecretSize)
		_, _ = io.ReadFull(t.rand, t.Secret)
	} else {
		t.SecretSize = uint(len(t.Secret))
	}
	if util.RemoveAllSpace(t.EncSecret) == "" {
		t.EncSecret = B32NoPadding.EncodeToString(t.Secret)
	}
	if _, ok := infrastructure.PatternMap[t.Pattern]; !ok {
		return fmt.Errorf("invalid pattern: %s", t.Pattern)
	}

	return nil
}

func (t *TOtp) checkArgs(args any) error {
	return util.CheckType(infrastructure.GetPatternArg(t.Pattern), args)
}

func (t *TOtp) genInternalArg() *dto.InternalArg {
	return &dto.InternalArg{
		Issuer:     t.Issuer,
		Skew:       t.Skew,
		SecretSize: t.SecretSize,
		Secret:     t.Secret,
		EncSecret:  t.EncSecret,
		Period:     t.Period,
		Digits:     t.Digits,
		Algorithm:  t.Algorithm,
		Pattern:    t.Pattern,
		OtpType:    enum.TOTP,
	}
}

func (t *TOtp) generateCodeForCounter(internalArg *dto.InternalArg, args any) (passCode string, err error) {
	p, _ := infrastructure.PatternMap[t.Pattern]
	// 计数
	counterByte, err := p.GenCounter(internalArg, args)

	// 计算
	secret := t.Secret
	// 自定义秘钥
	if val, err := util.GetFieldValue(args, "Secret"); err == nil {
		if v, ok := val.(string); ok && util.RemoveAllSpace(v) != "" {
			secret = []byte(v)
		}
	}
	mac := hmac.New(t.Algorithm.Hash, secret)
	_, _ = mac.Write(counterByte)
	sum := mac.Sum(nil)
	passCode, err = p.Calculation(internalArg, sum, args)

	return
}

func (t *TOtp) validateForCounter(internalArg *dto.InternalArg, passCode string, args any) bool {
	passCode = strings.TrimSpace(passCode)
	if newPassCode, err := t.generateCodeForCounter(internalArg, args); err == nil {
		if subtle.ConstantTimeCompare([]byte(newPassCode), []byte(passCode)) == 1 {
			return true
		}
	}

	return false
}

// GenerateCode generate dynamic password
func (t *TOtp) GenerateCode(args any) ([]string, error) {
	if err := t.checkArgs(args); err != nil {
		return nil, err
	}

	internalArg := t.genInternalArg()

	nowTime := time.Now().UTC()
	counter := int64(math.Floor(float64(nowTime.Unix()) / float64(t.Period)))
	newCounters := util.CalculateCounters(counter, 0)
	passCodes := make([]string, 0, len(newCounters))
	for _, c := range newCounters {
		internalArg.TimeCounter = c
		passCode, err := t.generateCodeForCounter(internalArg, args)
		if err != nil {
			return nil, fmt.Errorf("failed to generate dynamic code: %w", err)
		}
		passCodes = append(passCodes, passCode)
	}
	return passCodes, nil
}

// Validate verify dynamic password
func (t *TOtp) Validate(passCode string, args any) bool {
	if err := t.checkArgs(args); err != nil {
		return false
	}

	internalArg := t.genInternalArg()

	skew := t.Skew
	// 自定义skew
	if val, err := util.GetFieldValue(args, "Skew"); err == nil {
		if v, ok := val.(uint); ok && v > 0 {
			skew = v
		}
	}

	nowTime := time.Now().UTC()
	counter := int64(math.Floor(float64(nowTime.Unix()) / float64(t.Period)))
	newCounters := util.CalculateCounters(counter, skew)

	for _, c := range newCounters {
		internalArg.TimeCounter = c
		if t.validateForCounter(internalArg, passCode, args) {
			return true
		}
	}
	return false
}

// GenerateKey new key
func (t *TOtp) GenerateKey(args any) (string, error) {
	if err := t.checkArgs(args); err != nil {
		return "", err
	}

	internalArg := t.genInternalArg()
	p, _ := infrastructure.PatternMap[t.Pattern]

	return p.GenUrl(internalArg, args)
}

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
	"strings"
)

type HOtp struct {
	Issuer string // The name of the issuer/company

	SecretSize uint   // The size of the secret key to generate. Defaults to 20 bytes. Used when the key needs to be randomly generated
	Secret     []byte // The raw secret key. Defaults to a randomly generated key of size SecretSize
	EncSecret  string // The encoded secret key

	Digits    enum.DigitEnum     // The number of digits in the OTP
	Algorithm enum.AlgorithmEnum // The algorithm used for HMAC. Defaults to SHA1
	Pattern   enum.PatternEnum   // The OTP generation pattern
	rand      io.Reader          // The reader used for generating TOTP keys
}

// NewHOtp initializes and returns a new HOtp instance based on the provided CreateOtpCmd configuration.
func NewHOtp(cmd dto.CreateOtpCmd) (*HOtp, error) {
	hObj := &HOtp{
		Issuer:     cmd.Issuer,
		SecretSize: cmd.SecretSize,
		Secret:     []byte(cmd.Secret),
		EncSecret:  cmd.EncSecret,
		Digits:     cmd.Digits,
		Algorithm:  cmd.Algorithm,
		Pattern:    cmd.Pattern,
		rand:       rand.Reader,
	}
	if err := hObj.Init(); err != nil {
		return nil, fmt.Errorf("HOTP init failed: %w", err)
	}

	return hObj, nil
}

func (h *HOtp) Init() error {
	h.SecretSize = util.Ternary(h.SecretSize == 0, DefaultSecretSize, h.SecretSize)
	h.Digits = util.Ternary(h.Digits == 0, enum.DigitSix, h.Digits)
	if util.RemoveAllSpace(h.EncSecret) != "" {
		secret, err := util.DecodeBase32Secret(h.EncSecret)
		if err != nil {
			return fmt.Errorf("encSecret decode failed: %w", err)
		}
		h.Secret = secret
		h.SecretSize = uint(len(secret))
	}
	if util.RemoveAllSpace(string(h.Secret)) == "" {
		h.Secret = make([]byte, h.SecretSize)
		_, _ = io.ReadFull(h.rand, h.Secret)
	} else {
		h.SecretSize = uint(len(h.Secret))
	}
	if util.RemoveAllSpace(h.EncSecret) == "" {
		h.EncSecret = B32NoPadding.EncodeToString(h.Secret)
	}
	if _, ok := infrastructure.PatternMap[h.Pattern]; !ok {
		return fmt.Errorf("invalid pattern: %s", h.Pattern)
	}
	return nil
}

func (h *HOtp) checkArgs(args any) error {
	return util.CheckType(infrastructure.GetPatternArg(h.Pattern), args)
}

func (h *HOtp) genInternalArg() *dto.InternalArg {
	return &dto.InternalArg{
		Issuer:     h.Issuer,
		SecretSize: h.SecretSize,
		Secret:     h.Secret,
		EncSecret:  h.EncSecret,
		Digits:     h.Digits,
		Algorithm:  h.Algorithm,
		Pattern:    h.Pattern,
		OtpType:    enum.HOTP,
	}
}

func (h *HOtp) generateCodeForCounter(internalArg *dto.InternalArg, args any) (passCode string, err error) {
	p, _ := infrastructure.PatternMap[h.Pattern]
	// 计数
	counterByte, err := p.GenCounter(internalArg, args)

	// 计算
	secret := h.Secret
	// 自定义秘钥
	if val, err := util.GetFieldValue(args, "Secret"); err == nil {
		if v, ok := val.(string); ok && util.RemoveAllSpace(v) != "" {
			secret = []byte(v)
		}
	}
	mac := hmac.New(h.Algorithm.Hash, secret)
	_, _ = mac.Write(counterByte)
	sum := mac.Sum(nil)
	passCode, err = p.Calculation(internalArg, sum, args)

	return
}

func (h *HOtp) validateForCounter(internalArg *dto.InternalArg, passCode string, args any) bool {
	passCode = strings.TrimSpace(passCode)
	if newPassCode, err := h.generateCodeForCounter(internalArg, args); err == nil {
		if subtle.ConstantTimeCompare([]byte(newPassCode), []byte(passCode)) == 1 {
			return true
		}
	}

	return false
}

// GenerateCode generate dynamic password
func (h *HOtp) GenerateCode(args any) ([]string, error) {
	if err := h.checkArgs(args); err != nil {
		return nil, err
	}

	internalArg := h.genInternalArg()

	passCode, err := h.generateCodeForCounter(internalArg, args)
	if err != nil {
		return nil, err
	}

	return []string{passCode}, nil
}

// Validate verify dynamic password
func (h *HOtp) Validate(passCode string, args any) bool {
	if err := h.checkArgs(args); err != nil {
		return false
	}

	internalArg := h.genInternalArg()

	return h.validateForCounter(internalArg, passCode, args)
}

// GenerateKey new key
func (h *HOtp) GenerateKey(args any) (string, error) {
	if err := h.checkArgs(args); err != nil {
		return "", err
	}

	internalArg := h.genInternalArg()
	p, _ := infrastructure.PatternMap[h.Pattern]

	return p.GenUrl(internalArg, args)
}

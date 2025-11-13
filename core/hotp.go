package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/dhlanshan/otp/enum"
	"github.com/dhlanshan/otp/internal/command"
	"github.com/dhlanshan/otp/internal/common"
	"github.com/dhlanshan/otp/internal/util"
	"io"
	"net/url"
	"strings"
)

type HOtp struct {
	Issuer      string             // The name of the issuer/company
	AccountName string             // The user's account name (e.g., email address)
	SecretSize  uint               // The size of the secret key to generate. Defaults to 20 bytes. Used when the key needs to be randomly generated
	Secret      []byte             // The raw secret key. Defaults to a randomly generated key of size SecretSize
	EncSecret   string             // The encoded secret key
	Digits      enum.DigitEnum     // The number of digits in the OTP
	Algorithm   enum.AlgorithmEnum // The algorithm used for HMAC. Defaults to SHA1
	Pattern     enum.PatternEnum   // The OTP generation pattern
	Rand        io.Reader          // The reader used for generating TOTP keys
	Host        string             // The host of the key
}

// NewHOtp initializes and returns a new HOtp instance based on the provided CreateOtpCmd configuration.
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
		Rand:        rand.Reader,
		Host:        cmd.Host,
	}
	if err := hObj.Init(); err != nil {
		return nil, fmt.Errorf("HOTP init failed: %w", err)
	}
	// Load default pattern
	common.SetDefaultPattern()

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
		h.Digits = enum.DigitSix
	}
	if h.Rand == nil {
		h.Rand = rand.Reader
	}
	if h.EncSecret != "" {
		secret, err := util.DecodeBase32Secret(h.EncSecret)
		if err != nil {
			return fmt.Errorf("encSecret decode failed: %w", err)
		}
		h.Secret = secret
		h.SecretSize = uint(len(secret))
	}
	if len(h.Secret) == 0 {
		h.Secret = make([]byte, h.SecretSize)
		if _, err := io.ReadFull(h.Rand, h.Secret); err != nil {
			return fmt.Errorf("init secret failed: %w", err)
		}
	} else {
		h.SecretSize = uint(len(h.Secret))
	}
	if h.EncSecret == "" {
		h.EncSecret = common.B32NoPadding.EncodeToString(h.Secret)
	}

	return nil
}

func (h *HOtp) GenerateCodeForCounter(internalArg *InternalArg, args any) (passCode string, err error) {
	p, ok := common.PatternMap[h.Pattern]
	if !ok {
		return "", errors.New("invalid pattern")
	}

	// 计数
	counterByte, err := p.GenCounter(internalArg, args)

	// 计算
	mac := hmac.New(h.Algorithm.Hash, h.Secret)
	_, _ = mac.Write(counterByte)
	sum := mac.Sum(nil)
	passCode, err = p.Calculation(internalArg, sum, args)

	return
}

func (h *HOtp) ValidateForCounter(internalArg *InternalArg, passCode string, args any) (bool, error) {
	passCode = strings.TrimSpace(passCode)
	newPassCode, err := h.GenerateCodeForCounter(internalArg, args)
	if err != nil {
		return false, err
	}

	// 使用恒定时间比较以减少时序信息泄露
	if subtle.ConstantTimeCompare([]byte(newPassCode), []byte(passCode)) == 1 {
		return true, nil
	}
	return false, nil
}

// GenerateCode generate dynamic password
func (h *HOtp) GenerateCode(args any) ([]string, error) {
	internalArg := &InternalArg{}
	passCode, err := h.GenerateCodeForCounter(internalArg, args)
	if err != nil {
		return nil, err
	}

	return []string{passCode}, nil
}

// Validate verify dynamic password
func (h *HOtp) Validate(passCode string, args any) (bool, error) {
	internalArg := &InternalArg{}
	return h.ValidateForCounter(internalArg, passCode, args)
}

// GenerateKey new key
func (h *HOtp) GenerateKey() (string, error) {
	if h.Issuer == "" || h.AccountName == "" {
		return "", errors.New("lacking necessary account information")
	}

	val := url.Values{}
	val.Set("secret", h.EncSecret)
	val.Set("issuer", h.Issuer)
	val.Set("algorithm", h.Algorithm.String())
	val.Set("digits", h.Digits.String())
	val.Set("counter", "0")

	u := url.URL{Scheme: "otpauth", Host: h.Host, Path: "/" + h.Issuer + ":" + h.AccountName, RawQuery: util.EncodeQuery(val)}
	return util.NewKeyFromUrl(u.String())
}

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
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type TOtp struct {
	// 用户信息
	Issuer      string // The name of the issuer/company
	AccountName string // The user's account name (e.g., email address)

	// 可覆盖
	Skew       uint   // The allowed time period before or after the current time. When the value is 1, a maximum of two periods on either side of the specified time are allowed. Default is 0
	SecretSize uint   // The size of the secret key to generate. Defaults to 20 bytes. Used when the key needs to be randomly generated
	Secret     []byte // The raw secret key. Defaults to a randomly generated key of size SecretSize
	EncSecret  string // The encoded secret key

	// 不可覆盖
	Period    uint               // TOTP hash validity duration. Default is 30 seconds.
	Digits    enum.DigitEnum     // The number of digits in the OTP
	Algorithm enum.AlgorithmEnum // The algorithm used for HMAC. Defaults to SHA1
	Pattern   enum.PatternEnum   // The OTP generation pattern
	Rand      io.Reader          //
	Host      string             // The host of the key
}

// NewTOtp initializes and returns a new TOtp instance based on the provided CreateOtpCmd configuration.
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
		Host:        cmd.Host,
	}
	if err := tObj.Init(); err != nil {
		return nil, fmt.Errorf("TOTP init failed: %w", err)
	}
	// Load default pattern
	common.SetDefaultPattern()

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
		t.Digits = enum.DigitSix
	}
	if t.Rand == nil {
		t.Rand = rand.Reader
	}
	if t.EncSecret != "" {
		secret, err := util.DecodeBase32Secret(t.EncSecret)
		if err != nil {
			return fmt.Errorf("encSecret decode failed: %w", err)
		}
		t.Secret = secret
		t.SecretSize = uint(len(secret))
	}
	if len(t.Secret) == 0 {
		t.Secret = make([]byte, t.SecretSize)
		if _, err := io.ReadFull(t.Rand, t.Secret); err != nil {
			return fmt.Errorf("init secret failed: %w", err)
		}
	} else {
		t.SecretSize = uint(len(t.Secret))
	}
	if t.EncSecret == "" {
		t.EncSecret = common.B32NoPadding.EncodeToString(t.Secret)
	}
	if t.Pattern == enum.Steam {
		t.Digits = 5
		t.Period = 30
		t.Algorithm = enum.AlgorithmSHA1
		t.Host = "steam"
	}

	return nil
}

func (t *TOtp) generateCodeForCounter(internalArg *InternalArg, args any) (passCode string, err error) {
	p, _ := common.PatternMap[t.Pattern]
	// 计数
	counterByte, err := p.GenCounter(internalArg, args)

	// 计算
	mac := hmac.New(t.Algorithm.Hash, t.Secret)
	_, _ = mac.Write(counterByte)
	sum := mac.Sum(nil)
	passCode, err = p.Calculation(internalArg, sum, args)

	return
}

// GenerateCode generate dynamic password
func (t *TOtp) GenerateCode(args any) ([]string, error) {
	internalArg := &InternalArg{}

	nowTime := time.Now().UTC()
	counter := int64(math.Floor(float64(nowTime.Unix()) / float64(t.Period)))

	newCounters := util.CalculateCounters(counter, 0)

	passCodes := make([]string, 0, len(newCounters))
	for _, c := range newCounters {
		internalArg.Counter = c
		passCode, err := t.generateCodeForCounter(internalArg, args)
		if err != nil {
			return nil, fmt.Errorf("failed to generate dynamic code: %w", err)
		}
		passCodes = append(passCodes, passCode)
	}
	return passCodes, nil
}

func (t *TOtp) validateForCounter(internalArg *InternalArg, passCode string, args any) (bool, error) {
	passCode = strings.TrimSpace(passCode)
	newPassCode, err := t.generateCodeForCounter(internalArg, args)
	if err != nil {
		return false, err
	}

	// 使用恒定时间比较以减少时序信息泄露
	if subtle.ConstantTimeCompare([]byte(newPassCode), []byte(passCode)) == 1 {
		return true, nil
	}
	return false, nil
}

// Validate verify dynamic password
func (t *TOtp) Validate(passCode string, args any) (bool, error) {

	internalArg := &InternalArg{}

	nowTime := time.Now().UTC()
	counter := int64(math.Floor(float64(nowTime.Unix()) / float64(t.Period)))

	newCounters := util.CalculateCounters(counter, t.Skew)

	for _, c := range newCounters {
		internalArg.Counter = c
		isValid, err := t.validateForCounter(internalArg, passCode, args)
		if err != nil {
			return false, fmt.Errorf("validation failed: %w", err)
		}
		if isValid {
			return true, nil
		}
	}
	return false, errors.New("invalid dynamic code")
}

// GenerateKey new key
func (t *TOtp) GenerateKey() (string, error) {
	if t.Issuer == "" || t.AccountName == "" {
		return "", errors.New("lacking necessary account information")
	}

	val := url.Values{}
	val.Set("secret", t.EncSecret)
	val.Set("issuer", t.Issuer)
	val.Set("period", strconv.FormatUint(uint64(t.Period), 10))
	val.Set("algorithm", t.Algorithm.String())
	val.Set("digits", t.Digits.String())

	u := url.URL{Scheme: "otpauth", Host: t.Host, Path: "/" + t.Issuer + ":" + t.AccountName, RawQuery: util.EncodeQuery(val)}

	return util.NewKeyFromUrl(u.String())
}

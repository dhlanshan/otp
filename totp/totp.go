package totp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/dhlanshan/otp/hotp"
	"github.com/dhlanshan/otp/internal/command"
	"github.com/dhlanshan/otp/internal/common"
	"github.com/dhlanshan/otp/internal/enum"
	"github.com/dhlanshan/otp/internal/util"
	"io"
	"math"
	"net/url"
	"strconv"
	"time"
)

type TOtp struct {
	Issuer      string             // The name of the issuer/company
	AccountName string             // The user's account name (e.g., email address)
	Period      uint               // TOTP hash validity duration. Default is 30 seconds.
	Skew        uint               // The allowed time period before or after the current time. When the value is 1, a maximum of two periods on either side of the specified time are allowed. Default is 0
	SecretSize  uint               // The size of the secret key to generate. Defaults to 20 bytes. Used when the key needs to be randomly generated
	Secret      []byte             // The raw secret key. Defaults to a randomly generated key of size SecretSize
	EncSecret   string             // The encoded secret key
	Digits      enum.DigitEnum     // The number of digits in the OTP
	Algorithm   enum.AlgorithmEnum // The algorithm used for HMAC. Defaults to SHA1
	Pattern     enum.PatternEnum   // The OTP generation pattern
	Rand        io.Reader          //
	Host        string             // The host of the key
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
		return nil, errors.New(fmt.Sprintf("TOTP init failed: %s", err.Error()))
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
			return errors.New("EncSecret key decoding failed")
		}
		t.Secret = secret
		t.SecretSize = uint(len(secret))
	}
	if len(t.Secret) == 0 {
		t.Secret = make([]byte, t.SecretSize)
		if _, err := t.Rand.Read(t.Secret); err != nil {
			return errors.New("init Secret failed")
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
	if t.Pattern == "" {
		t.Pattern = enum.Standard
	}
	if t.Pattern == enum.Standard {
		t.Host = "totp"
	}

	return nil
}

// GenerateCode generate dynamic password
func (t *TOtp) GenerateCode(counters ...any) ([]string, error) {
	nowTime := time.Now().UTC()
	counter := int64(math.Floor(float64(nowTime.Unix()) / float64(t.Period)))

	_, pin := util.ParameterParsing(t.Pattern, counters)
	if t.Pattern == enum.Mobile && pin == "" {
		return nil, errors.New("missing pin parameter")
	}

	newCounters := util.CalculateCounters(counter, 0)
	hOpt := hotp.HOtp{Digits: t.Digits, Algorithm: t.Algorithm, Secret: t.Secret, Pattern: t.Pattern, Rand: t.Rand}

	passCodes := make([]string, 0, len(newCounters))
	for _, c := range newCounters {
		passCode, err := hOpt.GenerateCodeForCounter(c, pin)
		if err != nil {
			return nil, fmt.Errorf("failed to generate dynamic code: %w", err)
		}
		passCodes = append(passCodes, passCode)
	}
	return passCodes, nil
}

// Validate verify dynamic password
func (t *TOtp) Validate(passCode string, counters ...any) (bool, error) {
	nowTime := time.Now().UTC()
	counter := int64(math.Floor(float64(nowTime.Unix()) / float64(t.Period)))

	_, pin := util.ParameterParsing(t.Pattern, counters)
	if t.Pattern == enum.Mobile && pin == "" {
		return false, errors.New("missing pin parameter")
	}

	newCounters := util.CalculateCounters(counter, t.Skew)
	hObj := hotp.HOtp{Digits: t.Digits, Algorithm: t.Algorithm, Secret: t.Secret, Pattern: t.Pattern}

	for _, c := range newCounters {
		isValid, err := hObj.ValidateForCounter(passCode, c, pin)
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

	u := url.URL{Scheme: "otpauth", Host: t.Host, Path: "/" + url.PathEscape(t.Issuer+":"+t.AccountName), RawQuery: util.EncodeQuery(val)}

	return util.NewKeyFromUrl(u.String())
}

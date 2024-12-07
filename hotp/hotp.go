package hotp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
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
		return nil, errors.New(fmt.Sprintf("HOTP init failed: %s", err.Error()))
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
			return errors.New("EncSecret key decoding failed")
		}
		h.Secret = secret
		h.SecretSize = uint(len(secret))
	}
	if len(h.Secret) == 0 {
		h.Secret = make([]byte, h.SecretSize)
		if _, err := h.Rand.Read(h.Secret); err != nil {
			return errors.New("init Secret failed")
		}
	} else {
		h.SecretSize = uint(len(h.Secret))
	}
	if h.EncSecret == "" {
		h.EncSecret = common.B32NoPadding.EncodeToString(h.Secret)
	}
	if h.Pattern == "" {
		h.Pattern = enum.Standard
	}
	if h.Pattern == enum.Standard {
		h.Host = "hotp"
	}

	return nil
}

func (h *HOtp) GenerateCodeForCounter(counter uint64, pins ...string) (passCode string, err error) {
	if h.Digits == 0 {
		return "", errors.New("invalid password digits")
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	p, ok := common.PatternMap[h.Pattern]
	if !ok {
		return "", errors.New("invalid pattern")
	}
	buf, err = p.CounterFun(buf, pins...)
	if err != nil {
		return "", err
	}

	mac := hmac.New(h.Algorithm.Hash, h.Secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	if int(offset)+3 >= len(sum) {
		return "", fmt.Errorf("invalid offset, hashSum length is too short")
	}
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	dl := h.Digits.Length()
	passCode = p.CalculationFun(value, dl, h.Digits)

	return
}

func (h *HOtp) ValidateForCounter(passCode string, counter uint64, pin string) (bool, error) {
	passCode = strings.TrimSpace(passCode)
	if len(passCode) != h.Digits.Length() {
		return false, errors.New("invalid password digits")
	}

	newPassCode, err := h.GenerateCodeForCounter(counter, pin)
	if err != nil {
		return false, err
	}

	if !(subtle.ConstantTimeCompare([]byte(newPassCode), []byte(passCode)) == 1) {
		return false, nil
	}

	return true, nil
}

// GenerateCode generate dynamic password
func (h *HOtp) GenerateCode(counters ...any) ([]string, error) {
	if len(counters) == 0 {
		return nil, errors.New("counters is empty")
	}

	counter, pin := util.ParameterParsing(h.Pattern, counters)
	if counter == 0 {
		return nil, errors.New("missing counter parameter")
	}
	if h.Pattern == enum.Mobile && pin == "" {
		return nil, errors.New("missing pin parameter")
	}

	passCode, err := h.GenerateCodeForCounter(counter, pin)
	if err != nil {
		return nil, err
	}

	return []string{passCode}, nil
}

// Validate verify dynamic password
func (h *HOtp) Validate(passCode string, counters ...any) (bool, error) {
	if len(counters) == 0 {
		return false, errors.New("counters is empty")
	}

	counter, pin := util.ParameterParsing(h.Pattern, counters)
	if counter == 0 {
		return false, errors.New("missing counter parameter")
	}
	if h.Pattern == enum.Mobile && pin == "" {
		return false, errors.New("missing pin parameter")
	}

	return h.ValidateForCounter(passCode, counter, pin)
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

	u := url.URL{Scheme: "otpauth", Host: h.Host, Path: "/" + h.Issuer + ":" + h.AccountName, RawQuery: util.EncodeQuery(val)}

	return util.NewKeyFromUrl(u.String())
}

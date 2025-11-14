package realize

import (
	"encoding/binary"
	"errors"
	"github.com/dhlanshan/otp/dto"
	"github.com/dhlanshan/otp/enum"
	"github.com/dhlanshan/otp/internal/util"
	"github.com/dhlanshan/otp/truncate"
	"math"
	"net/url"
	"strconv"
)

type StandardPattern struct{}

func (sp *StandardPattern) GenCounter(internalArg *dto.InternalArg, args any) ([]byte, error) {
	arg := args.(*dto.StandardArg)
	counter := arg.Counter
	if internalArg.TimeCounter > 0 {
		counter = internalArg.TimeCounter
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	return buf, nil
}

func (sp *StandardPattern) Calculation(internalArg *dto.InternalArg, hash []byte, args any) (string, error) {
	trc, err := truncate.StandardTruncate(hash)
	if err != nil {
		return "", err
	}
	dl := internalArg.Digits.Length()
	mod := trc % int64(math.Pow10(dl))

	return internalArg.Digits.Format(int32(mod)), nil
}

func (sp *StandardPattern) GenUrl(internalArg *dto.InternalArg, args any) (string, error) {
	arg := args.(*dto.StandardArg)

	if internalArg.Issuer == "" || arg.AccountName == "" {
		return "", errors.New("lacking necessary account information")
	}

	host := util.Ternary(internalArg.OtpType == enum.HOTP, "hotp", "totp")

	val := url.Values{}
	val.Set("secret", internalArg.EncSecret)
	val.Set("issuer", internalArg.Issuer)
	val.Set("period", strconv.FormatUint(uint64(internalArg.Period), 10))
	val.Set("algorithm", internalArg.Algorithm.String())
	val.Set("digits", internalArg.Digits.String())

	u := url.URL{Scheme: "otpauth", Host: host, Path: "/" + internalArg.Issuer + ":" + arg.AccountName, RawQuery: util.EncodeQuery(val)}

	return util.NewKeyFromUrl(u.String())
}

package util

import (
	"encoding/base32"
	"github.com/dhlanshan/otp/enum"
	"net/url"
	"sort"
	"strings"
)

// DecodeBase32Secret decode Base32 key
func DecodeBase32Secret(encSecret string) ([]byte, error) {
	encSecret = strings.ToUpper(strings.TrimSpace(encSecret))
	if n := len(encSecret) % 8; n != 0 {
		encSecret += strings.Repeat("=", 8-n)
	}
	return base32.StdEncoding.DecodeString(encSecret)
}

// CalculateCounters calculate all counter values within the time offset window.
func CalculateCounters(baseCounter int64, skew uint) []uint64 {
	counters := []uint64{uint64(baseCounter)}
	for i := 1; i <= int(skew); i++ {
		counters = append(counters, uint64(baseCounter+int64(i)))
		counters = append(counters, uint64(baseCounter-int64(i)))
	}
	return counters
}

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

func NewKeyFromUrl(orig string) (string, error) {
	s := strings.TrimSpace(orig)
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}

	return u.String(), nil
}

func ParameterParsing(pattern enum.PatternEnum, counters ...any) (counter uint64, pin string) {
	switch pattern {
	case enum.Mobile:
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

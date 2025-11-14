package util

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"reflect"
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

// CheckType 校验传入数据类型是否匹配
func CheckType(expect reflect.Type, v any) error {
	if v == nil {
		return fmt.Errorf("invalid type: nil")
	}

	actual := reflect.TypeOf(v)

	// 去掉多级指针
	for actual.Kind() == reflect.Pointer {
		actual = actual.Elem()
	}

	for expect.Kind() == reflect.Pointer {
		expect = expect.Elem()
	}

	// 如果预期是接口，则判断实现
	if expect.Kind() == reflect.Interface {
		if !actual.Implements(expect) {
			return fmt.Errorf("type %v does not implement %v", actual, expect)
		}
		return nil
	}

	// 普通类型直接比较
	if actual != expect {
		return fmt.Errorf("invalid type %v, expect %v", actual, expect)
	}

	return nil
}

func GetFieldValue(obj any, fieldName string) (any, error) {
	v := reflect.ValueOf(obj)
	// 如果是指针，取 Elem()
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	// 必须是结构体
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("传入的不是结构体类型")
	}
	// 查找字段
	f := v.FieldByName(fieldName)
	if !f.IsValid() {
		return nil, fmt.Errorf("字段不存在: %s", fieldName)
	}

	return f.Interface(), nil
}

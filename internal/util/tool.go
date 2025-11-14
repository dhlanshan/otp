package util

import (
	"strings"
	"unicode"
)

// Ternary 三目运算
func Ternary[T any](exp bool, e1, e2 T) T {
	if exp {
		return e1
	}
	return e2
}

func RemoveAllSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1 // 删除该字符
		}
		return r
	}, s)
}

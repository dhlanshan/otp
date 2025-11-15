package infrastructure

import (
	"fmt"
	"github.com/dhlanshan/otp/dto"
	"github.com/dhlanshan/otp/enum"
	"github.com/dhlanshan/otp/internal/abstract"
	"github.com/dhlanshan/otp/internal/realize"
	"reflect"
	"sync"
)

var (
	PatternMap    = map[enum.PatternEnum]abstract.Pattern{}
	PatternArgMap = map[enum.PatternEnum]reflect.Type{}

	patternInitOnce sync.Once
	registryMu      sync.RWMutex
)

// RegisterPattern 注册模式
func RegisterPattern[T any](patternName enum.PatternEnum, obj abstract.Pattern, _ T) {
	registryMu.Lock()
	defer registryMu.Unlock()

	// 强制要求 obj 必须实现 Pattern
	var _ abstract.Pattern = obj

	var zero T
	t := reflect.TypeOf(zero)

	// t 为 struct 或 *struct
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		panic(fmt.Errorf("Pattern(%v) 的参数类型必须为 struct 或 struct 指针，实际: %v", patternName, t.Kind()))
	}

	PatternMap[patternName] = obj
	PatternArgMap[patternName] = t
}

func GetPatternArg(pattern enum.PatternEnum) reflect.Type {
	v, ok := PatternArgMap[pattern]
	if !ok {
		return nil
	}
	return v
}

func init() {
	patternInitOnce.Do(func() {
		PatternMap[enum.Standard] = &realize.StandardPattern{}
		PatternArgMap[enum.Standard] = reflect.TypeOf(&dto.StandardArg{})
	})
}

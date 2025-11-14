package infrastructure

import (
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
func RegisterPattern[T any](pattern enum.PatternEnum, obj abstract.Pattern) {
	registryMu.Lock()
	defer registryMu.Unlock()

	var zero T
	t := reflect.TypeOf(zero)

	PatternMap[pattern] = obj
	PatternArgMap[pattern] = t
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

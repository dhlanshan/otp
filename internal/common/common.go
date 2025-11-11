package common

import (
	"encoding/base32"
	"github.com/dhlanshan/otp/enum"
	"github.com/dhlanshan/otp/internal/abstract"
	"github.com/dhlanshan/otp/internal/realize"
	"sync"
)

// 默认配置
const (
	DefaultIssuer      = "灯火阑珊"
	DefaultAccountName = "bee"
	DefaultPeriod      = 30
	DefaultSecretSize  = 20
)

var B32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

var (
	PatternMap      = map[enum.PatternEnum]abstract.Pattern{}
	patternInitOnce sync.Once
)

func SetDefaultPattern() {
	// 仍保留此函数以兼容现有调用，但底层已由 init/Once 初始化
	patternInitOnce.Do(func() {
		PatternMap[enum.Standard] = &realize.StandardPattern{}
		PatternMap[enum.Steam] = &realize.SteamPattern{}
		PatternMap[enum.Mobile] = &realize.MobilePattern{}
	})
}

func init() {
	patternInitOnce.Do(func() {
		PatternMap[enum.Standard] = &realize.StandardPattern{}
		PatternMap[enum.Steam] = &realize.SteamPattern{}
		PatternMap[enum.Mobile] = &realize.MobilePattern{}
	})
}

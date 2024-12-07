package common

import (
	"encoding/base32"
	"github.com/dhlanshan/otp/enum"
	"github.com/dhlanshan/otp/internal/abstract"
	"github.com/dhlanshan/otp/internal/realize"
)

// 默认配置
const (
	DefaultIssuer      = "灯火阑珊"
	DefaultAccountName = "bee"
	DefaultPeriod      = 30
	DefaultSecretSize  = 20
)

var B32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

var PatternMap = map[enum.PatternEnum]abstract.Pattern{}

func SetDefaultPattern() {
	// Standard
	PatternMap[enum.Standard] = &realize.StandardPattern{}
	// Steam
	PatternMap[enum.Steam] = &realize.SteamPattern{}
	// Mobile
	PatternMap[enum.Mobile] = &realize.MobilePattern{}
}

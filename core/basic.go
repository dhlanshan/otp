package core

import "encoding/base32"

var B32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// 默认配置
const (
	DefaultIssuer      = "灯火阑珊"
	DefaultAccountName = "bee"
	DefaultPeriod      = 30
	DefaultSecretSize  = 20
)

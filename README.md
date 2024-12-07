# OTP - 多功能一次性密码（HOTP / TOTP / Steam）安全库

[![Go Version](https://img.shields.io/badge/Go-1.23.3-blue)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

`otp` 是一个用 Go 编写的高性能安全库，支持 [HOTP](https://datatracker.ietf.org/doc/html/rfc4226)、[TOTP](https://datatracker.ietf.org/doc/html/rfc6238) 和 Steam 规范的一次性密码生成与验证，广泛适用于双因素认证 (2FA)、游戏安全及其他需要动态密码的场景。

---

## 功能与特性

### 🔒 **全面支持多种 OTP 类型**
- **HOTP**（基于 HMAC 的一次性密码）：适合计数器驱动的动态密码生成。
- **TOTP**（基于时间的一次性密码）：符合时间步长规范，常见于主流的 2FA 实现。
- **Steam**：专为 Steam 平台优化的动态密码生成，兼容其特定字符集与格式。

### ⚡ **高性能与可扩展性**
- 高效的哈希计算，适合高并发使用场景。
- 支持多种哈希算法（如 SHA1、SHA256、SHA512 等）。
- 灵活的配置，支持自定义密码长度、时间步长、计数器等参数。

### 📦 **简洁易用的 API**
- 专为开发者设计的友好接口，便于快速集成与使用。
- 提供简单明了的用法示例。

---

## 示例

- 生成一个类型为hotp,时间步长为30秒的6位的令牌地址
```go
package main

import (
	"fmt"
	"github.com/dhlanshan/otp"
)

func main() {
	cmd := &otp.CreateOtpCmd{Issuer: "上天揽月", AccountName: "bee", OtpType: otp.HOTP}
	key, err := otp.GenerateKey(cmd)
	fmt.Println(key, err)
	// 输出: otpauth://hotp/%E4%B8%8A%E5%A4%A9%E6%8F%BD%E6%9C%88:bee?algorithm=SHA1&digits=6&issuer=%E4%B8%8A%E5%A4%A9%E6%8F%BD%E6%9C%88&secret=E6GI4IVJTVFFIDA67SDJ5KC647AZHQTM <nil>
}
```

- HOTP类型 通过指定的秘钥来生成动态密码
```go
package main

import (
	"fmt"
	"github.com/dhlanshan/otp"
)

func main() {
	cmd := &otp.CreateOtpCmd{Issuer: "上天揽月", AccountName: "bee", OtpType: otp.HOTP, EncSecret: "E6GI4IVJTVFFIDA67SDJ5KC647AZHQTM"}
	code, err := otp.GenerateCode(cmd, uint64(1))
	fmt.Println(code, err)
	// 输出:956878 <nil>
}
```
- HOTP类型 校验密码
```go
package main

import (
	"fmt"
	"github.com/dhlanshan/otp"
)

func main() {
	cmd := &otp.CreateOtpCmd{Issuer: "上天揽月", AccountName: "bee", OtpType: otp.HOTP, EncSecret: "E6GI4IVJTVFFIDA67SDJ5KC647AZHQTM"}
	code := otp.Validate(cmd, "956878", uint64(1))
	fmt.Println(code)
	// 输出:true
}
```
- TOTP 生成令牌地址
```go
package main

import (
	"fmt"
	"github.com/dhlanshan/otp"
)

func main() {
	cmd := &otp.CreateOtpCmd{Issuer: "上天揽月", AccountName: "bee", OtpType: otp.TOTP, EncSecret: "E6GI4IVJTVFFIDA67SDJ5KC647AZHQTM"}
	key, err := otp.GenerateKey(cmd)
	fmt.Println(key, err)
	// 输出:otpauth://totp/%25E4%25B8%258A%25E5%25A4%25A9%25E6%258F%25BD%25E6%259C%2588:bee?algorithm=SHA1&digits=6&issuer=%E4%B8%8A%E5%A4%A9%E6%8F%BD%E6%9C%88&period=30&secret=E6GI4IVJTVFFIDA67SDJ5KC647AZHQTM
}
```

- TOTP 生成密码
```go
package main

import (
	"fmt"
	"github.com/dhlanshan/otp"
)

func main() {
	cmd := &otp.CreateOtpCmd{Issuer: "上天揽月", AccountName: "bee", OtpType: otp.TOTP, EncSecret: "E6GI4IVJTVFFIDA67SDJ5KC647AZHQTM"}
	code, err := otp.GenerateCode(cmd)
	fmt.Println(code, err)
}
```

- TOTP 校验
```go
package main

import (
	"fmt"
	"github.com/dhlanshan/otp"
)

func main() {
	cmd := &otp.CreateOtpCmd{Issuer: "上天揽月", AccountName: "bee", OtpType: otp.TOTP, EncSecret: "E6GI4IVJTVFFIDA67SDJ5KC647AZHQTM"}
	res := otp.Validate(cmd, "380496")
	fmt.Println(res)
}
```

- 校验,允许当前时间前后的时间段(上一个密码和将要生成的密码以及当前密码都可验证通过)
```go
package main

import (
	"fmt"
	"github.com/dhlanshan/otp"
)

func main() {
	cmd := &otp.CreateOtpCmd{Issuer: "上天揽月", AccountName: "bee", OtpType: otp.TOTP, EncSecret: "E6GI4IVJTVFFIDA67SDJ5KC647AZHQTM", Skew: 1}
	res := otp.Validate(cmd, "109509")
	fmt.Println(res)
}
```

- Steam 模式
```go
package main

import (
	"fmt"
	"github.com/dhlanshan/otp"
	"github.com/dhlanshan/otp/enum"
)

func main() {
	cmd := &otp.CreateOtpCmd{Issuer: "上天揽月", AccountName: "bee", OtpType: otp.TOTP, EncSecret: "E6GI4IVJTVFFIDA67SDJ5KC647AZHQTM", Pattern: enum.Steam}
	key, err := otp.GenerateKey(cmd)
	fmt.Println(key, err)
}

```

- 自定义模式 (自定义模式需实现CounterFun和CalculationFun方法)
```go


```
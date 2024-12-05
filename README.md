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

## 安装

确保您的 Go 版本为 **1.23.3** 或更高版本。运行以下命令安装：

```bash
go get -u github.com/your-repo/otp
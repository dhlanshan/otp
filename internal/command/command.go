package command

import (
	"github.com/dhlanshan/otp/internal/enum"
)

// CreateOtpCmd OTP command
type CreateOtpCmd struct {
	Issuer      string             // The name of the issuer/company
	AccountName string             // The user's account name (e.g., email address)
	OtpType     string             // otp type
	Period      uint               // TOTP hash validity duration. Default is 30 seconds.
	Skew        uint               // The allowed time period before or after the current time. When the value is 1, a maximum of two periods on either side of the specified time are allowed. Default is 0
	SecretSize  uint               // The size of the secret key to generate. Defaults to 20 bytes. Used when the key needs to be randomly generated
	Secret      string             // The raw secret key. Defaults to a randomly generated key of size SecretSize
	EncSecret   string             // The encoded secret key
	Digits      enum.DigitEnum     // The number of digits in the OTP
	Algorithm   enum.AlgorithmEnum // The algorithm used for HMAC. Defaults to SHA1
	Pattern     enum.PatternEnum   // The OTP generation pattern
	Host        string             // The host of the key
}

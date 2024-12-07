package enum

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

type PatternEnum string

const (
	Standard PatternEnum = "standard" // standard
	Steam    PatternEnum = "steam"    // steam
	Mobile   PatternEnum = "mobile"   // mobile
)

type AlgorithmEnum int

const (
	AlgorithmSHA1 AlgorithmEnum = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

func (a AlgorithmEnum) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}
	panic("unreached")
}

func (a AlgorithmEnum) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}
	panic("unreached")
}

type DigitEnum int

const (
	DigitFour  DigitEnum = 4
	DigitSix   DigitEnum = 6
	DigitEight DigitEnum = 8
)

// Format converts an integer into the zero-filled size for this Digits.
func (d DigitEnum) Format(in int32) string {
	f := fmt.Sprintf("%%0%dd", d)
	return fmt.Sprintf(f, in)
}

// Length returns the number of characters for this Digits.
func (d DigitEnum) Length() int {
	return int(d)
}

func (d DigitEnum) String() string {
	return fmt.Sprintf("%d", d)
}

package truncate

import "fmt"

// StandardTruncate 标准RFC4226动态截取
func StandardTruncate(hash []byte) (int64, error) {
	offset := int(hash[len(hash)-1] & 0x0f)
	if offset+3 >= len(hash) {
		return 0, fmt.Errorf("invalid offset: %d", offset)
	}
	b0 := int(hash[offset]) & 0xff
	b1 := int(hash[offset+1]) & 0xff
	b2 := int(hash[offset+2]) & 0xff
	b3 := int(hash[offset+3]) & 0xff

	value := int64(((b0 & 0x7f) << 24) | (b1 << 16) | (b2 << 8) | b3)

	return value, nil
}

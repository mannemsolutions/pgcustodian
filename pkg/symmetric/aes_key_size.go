package symmetric

import "fmt"

/*
AESKeySize is used internally as an enum.
The value is a direct reference to the number of bytes needed for a AES Key.
*/
type AESKeySize uint8

const (
	// AES-128 requires a 128 bit (16 byte) key
	AESKeySize128 AESKeySize = 16
	// AES-192 requires a 192 bit (24 byte) key
	AESKeySize192 AESKeySize = 24
	// AES-256 requires a 256 bit (32 byte) key
	AESKeySize256 AESKeySize = 32
)

// AESKeySizeOptions returns a list of AESKeySizes
func AESKeySizeOptions() (options []AESKeySize) {
	for _, size := range AesKeyEnumToSize {
		options = append(options, size)
	}
	return options
}

// ToAESKeyEnum is used to get the Key Enum (string) from an AESKeySize (uint8)
func (e *AESKeySize) ToAESKeyEnum() AESKeyEnum {
	for key, value := range AesKeyEnumToSize {
		if value == *e {
			return key
		}
	}
	panic(fmt.Errorf("failed to convert AESKeySize %d to AESKeySize", e))
}

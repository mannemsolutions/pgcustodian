package symmetric

/*
AESKeyEnum is a string enum that is externally used as a cobra Flag enum.
Internally the crypt module uses AESKeySize which can be interchanged with ToAESKeySIze / ToAESKeyEnum methods.
*/

import (
	"fmt"
)

// AESKeyEnum can be used as an enum as a cobra Flag.
type AESKeyEnum string

const (
	// AESKeyEnum128 is the enum for aes-128 KeySize
	AESKeyEnum128 AESKeyEnum = "aes-128"
	// AESKeyEnum192 is the enum for aes-192 KeySize
	AESKeyEnum192 AESKeyEnum = "aes-192"
	// AESKeyEnum256 is the enum for aes-256 KeySize
	AESKeyEnum256 AESKeyEnum = "aes-256"
	// AESKeyEnum type
	AESKeyEnumType = "AESKeyEnum"
)

var (
	//aesKeyEnumToSize is an internal mapping between Enum and Size
	AesKeyEnumToSize = map[AESKeyEnum]AESKeySize{
		AESKeyEnum128: AESKeySize128,
		AESKeyEnum192: AESKeySize192,
		AESKeyEnum256: AESKeySize256,
	}
)

// AESKeyEnumOptions derives and returns a list of all options from aesKeyEnumToSize
func AESKeyEnumOptions() (options []AESKeyEnum) {
	for key := range AesKeyEnumToSize {
		options = append(options, key)
	}
	return options
}

// String is used both by fmt.Print and by Cobra in help text
func (e *AESKeyEnum) String() string {
	return string(*e)
}

// ToAESKeySize is used to get the Key Size (uint8) from a AESKeyEnum (string)
func (e *AESKeyEnum) ToAESKeySize() AESKeySize {
	if size, exists := AesKeyEnumToSize[*e]; !exists {
		panic(fmt.Errorf("failed to convert AESKeyEnum %s to AESKeySize", e))
	} else {
		return size
	}
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *AESKeyEnum) Set(v string) error {
	switch v {
	case string(AESKeyEnum128), string(AESKeyEnum192), string(AESKeyEnum256):
		*e = AESKeyEnum(v)
		return nil
	default:
		return fmt.Errorf(`must be one of %v`, AESKeyEnumOptions())
	}
}

// Type is only used in help text
func (e *AESKeyEnum) Type() string {
	return AESKeyEnumType
}

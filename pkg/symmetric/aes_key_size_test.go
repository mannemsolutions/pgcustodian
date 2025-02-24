package symmetric_test

import (
	"mannemsolutions/pgcustodian/pkg/symmetric"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAESKeySizeOptions(t *testing.T) {
	var expected = []symmetric.AESKeySize{
		symmetric.AESKeySize128,
		symmetric.AESKeySize192,
		symmetric.AESKeySize256,
	}
	o := symmetric.AESKeySizeOptions()
	assert.ElementsMatch(t, expected, o, "The following options should be provided")
}

func TestAESKeySize(t *testing.T) {

	const (
		validKeySize     = symmetric.AESKeySize128
		validStringValue = "aes-128"
	)
	var (
		enum           symmetric.AESKeyEnum
		convertedEnum  symmetric.AESKeyEnum
		invalidKeySize symmetric.AESKeySize = 1
	)

	assert.Panics(t, func() { enum = invalidKeySize.ToAESKeyEnum() }, "ToAESKeyEnum() on an AESKeyEnum with invalid string value should panic")
	assert.Equal(t, "", enum.String(), "ToAESKeyEnum() on an AESKeyEnum with invalid string value should return empty string")
	for enum, keySize := range symmetric.AesKeyEnumToSize {
		assert.NotPanics(t, func() { convertedEnum = keySize.ToAESKeyEnum() }, `ToAESKeyEnum(%d) on an AESKeyEnum with invalid string value should panic`, validKeySize)
		assert.Equal(t, enum, convertedEnum, validKeySize)
	}

}

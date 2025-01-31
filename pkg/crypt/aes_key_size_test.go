package crypt_test

import (
	"mannemsolutions/pgcustodian/pkg/crypt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAESKeySizeOptions(t *testing.T) {
	var expected = []crypt.AESKeySize{
		crypt.AESKeySize128,
		crypt.AESKeySize192,
		crypt.AESKeySize256,
	}
	o := crypt.AESKeySizeOptions()
	assert.ElementsMatch(t, expected, o, "The following options should be provided")
}

func TestAESKeySize(t *testing.T) {

	const (
		validKeySize     = crypt.AESKeySize128
		validStringValue = "aes-128"
	)
	var (
		enum           crypt.AESKeyEnum
		convertedEnum  crypt.AESKeyEnum
		invalidKeySize crypt.AESKeySize = 1
	)

	assert.Panics(t, func() { enum = invalidKeySize.ToAESKeyEnum() }, "ToAESKeyEnum() on an AESKeyEnum with invalid string value should panic")
	assert.Equal(t, "", enum.String(), "ToAESKeyEnum() on an AESKeyEnum with invalid string value should return empty string")
	for enum, keySize := range crypt.AesKeyEnumToSize {
		assert.NotPanics(t, func() { convertedEnum = keySize.ToAESKeyEnum() }, `ToAESKeyEnum(%d) on an AESKeyEnum with invalid string value should panic`, validKeySize)
		assert.Equal(t, enum, convertedEnum, validKeySize)
	}

}

package crypt_test

import (
	"mannemsolutions/pgcustodian/pkg/crypt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAESKeyEnumOptions(t *testing.T) {
	var expected = []crypt.AESKeyEnum{
		crypt.AESKeyEnum128,
		crypt.AESKeyEnum192,
		crypt.AESKeyEnum256,
	}
	o := crypt.AESKeyEnumOptions()
	assert.ElementsMatch(t, expected, o, "The following options should be provided")
}

func TestAESKeyEnum(t *testing.T) {
	const (
		invalidStringValue = "testing"
		validStringValue   = "aes-128"
		validKeySize       = crypt.AESKeySize128
	)
	var keySize crypt.AESKeySize
	var enum crypt.AESKeyEnum

	assert.Error(t, enum.Set(invalidStringValue), "setting enum to improper value should return an error")

	enum = invalidStringValue
	assert.Equal(t, invalidStringValue, enum.String())
	assert.Panics(t, func() { keySize = enum.ToAESKeySize() }, "ToAESKeySize() on an AESKeyEnum with invalid string value should panic")

	assert.NoError(t, enum.Set(validStringValue), "setting enum to proper value should not return an error")
	assert.NotPanics(t, func() { keySize = enum.ToAESKeySize() }, "ToAESKeySize() on an AESKeyEnum with valid string value should not panic")
	assert.Equal(t, validKeySize, keySize, `AESKeyEnum("%s").ToAESKeySize() should properly map to AESKeySize(%d)`, validStringValue, validKeySize)
	assert.Equal(t, crypt.AESKeyEnumType, enum.Type())
}

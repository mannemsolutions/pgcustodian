package passwordGen_test

import (
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomPasswordSucces(t *testing.T) {
	const (
		length = 20
		count  = 10
	)
	chars := passwordGen.AllBytes
	generated := make(map[string]bool)
	for i := 0; i < count; i++ {
		password := passwordGen.RandomPassword(length, chars)
		assert.Len(t, password, length, "generated passwords should have length as specified")
		generated[password] = true
	}
	assert.Len(t, generated, count, "all %d passwords should be unique", count)
}

func TestRandomPasswordFails(t *testing.T) {
	assert.PanicsWithError(t,
		"cannot generate random password with less then 2 characters to choose from",
		func() {
			_ = passwordGen.RandomPassword(10, "")
		},
		"Panic when not supplying any characters",
	)

	assert.PanicsWithError(t,
		"password with zero characters is not random",
		func() {
			_ = passwordGen.RandomPassword(0, "")
		},
		"Panic when asking password of 0 length",
	)
}

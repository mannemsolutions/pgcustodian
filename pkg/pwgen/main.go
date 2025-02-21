package passwordGen

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

const (
	LowercaseBytes = "abcdefghijklmnopqrstuvwxyz"
	UppercaseBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	LetterBytes    = LowercaseBytes + UppercaseBytes
	SpecialBytes   = "!@#$%^&*()_+-=[]{}\\|;':\",.<>/?`~"
	NumBytes       = "0123456789"
	AllBytes       = LetterBytes + SpecialBytes + NumBytes
)

func RandomPassword(length uint, chars string) string {
	var password []byte
	l := big.NewInt(int64(len(chars)))

	if length < 1 {
		panic(errors.New("password with zero characters is not random"))
	}
	if len(chars) < 2 {
		panic(errors.New("cannot generate random password with less then 2 characters to choose from"))
	}
	for i := 0; i < int(length); i++ {
		if randNum, err := rand.Int(rand.Reader, l); err != nil {
			panic(fmt.Errorf("could not generate random password: %w", err))
		} else {
			password = append(password, chars[randNum.Int64()])
		}
	}
	return string(password)
}

package crypt_test

import (
	"bufio"
	"bytes"
	"fmt"
	"mannemsolutions/pgcustodian/pkg/crypt"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPasswordToKey(t *testing.T) {
	keys := make(map[string]bool)
	passwords := make(map[string]bool)
	for _, keySize := range []crypt.AESKeySize{crypt.AESKeySize128, crypt.AESKeySize192, crypt.AESKeySize256} {
		keyEnum := keySize.ToAESKeyEnum()
		for _, pwSize := range []uint{1, 16, 255} {
			password := passwordGen.RandomPassword(pwSize, passwordGen.AllBytes)
			passwords[password] = true
			key := crypt.PasswordToKey(password, keySize)
			keys[string(key)] = true
			assert.Len(t, key, int(keySize), "key size for %s passwords should be %d", keyEnum, keySize)
		}
	}
	assert.Len(t, keys, 9, "should have 3*3 different keys")
	assert.Len(t, passwords, 9, "should have 3*3 different passwords")
}

func fileSize(path string) (int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	// get the size
	return fi.Size(), nil
}

func fileSha(path string) ([]byte, error) {
	if dat, err := os.ReadFile(path); err != nil {
		return nil, err
	} else {
		return crypt.PasswordToKey(string(dat), crypt.AESKeySize256), nil
	}
}

func TestStreams(t *testing.T) {
	const (
		inFile        = "inFile"
		encryptedFile = "encryptedFile"
	)
	tmpDir, err := os.MkdirTemp("", "StreamsTest")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}

	filePath := filepath.Join(tmpDir, encryptedFile)
	t.Logf("encrypting to %s", filePath)
	generated := []byte(passwordGen.RandomPassword(1024, passwordGen.AllBytes))
	generatedSha := crypt.PasswordToKey(string(generated), crypt.AESKeySize256)
	reader := bufio.NewReader(bytes.NewReader(generated))
	password := []byte(passwordGen.RandomPassword(10, passwordGen.AllBytes))
	key := crypt.PasswordToKey(string(password), crypt.AESKeySize256)

	// encryption
	written, err := crypt.EncryptToFile(key, reader, filePath)
	assert.NoError(t, err, "We should be able to encrypt this")
	assert.FileExists(t, filePath, "EncryptToFile should have created %s", filePath)
	size, err := fileSize(filePath)
	assert.NoError(t, err, "We should be able to read fle size")
	assert.Equal(t, written, size, "written should report same number of bytes as filesize")
	t.Logf("written %d bytes to %s", written, filePath)
	fileSha, err := fileSha(filePath)
	assert.NoError(t, err, "Should be able to get sha from file")
	assert.NotEqual(t, generatedSha, fileSha, "after encryption, file should have different sha then generated input")

	// decryption
	var decrypted bytes.Buffer
	read, err := crypt.DecryptFromFile(key, filePath, bufio.NewWriter(&decrypted))
	assert.NoError(t, err, "We should be able to decrypt this")
	t.Logf("read %d bytes from %s", read, filePath)
	decryptedSha := crypt.PasswordToKey(decrypted.String(), crypt.AESKeySize256)
	assert.Equal(t, len(generated), len(decrypted.Bytes()), "after decryption, data should have same length as generated input")
	assert.Equal(t, generatedSha, decryptedSha, "after decryption, data should have same sha as generated input")
}

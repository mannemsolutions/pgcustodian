package symmetric_test

import (
	"bufio"
	"bytes"
	"fmt"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/symmetric"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordToKey(t *testing.T) {
	keys := make(map[string]bool)
	passwords := make(map[string]bool)
	for _, keySize := range []symmetric.AESKeySize{symmetric.AESKeySize128, symmetric.AESKeySize192, symmetric.AESKeySize256} {
		keyEnum := keySize.ToAESKeyEnum()
		for _, pwSize := range []uint{1, 16, 255} {
			password := passwordGen.RandomPassword(pwSize, passwordGen.AllBytes)
			passwords[password] = true
			key := symmetric.PasswordToKey(password, keySize)
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
		return symmetric.PasswordToKey(string(dat), symmetric.AESKeySize256), nil
	}
}

func decryptShaHelper(t *testing.T, key []byte, filePath string) []byte {
	var decrypted bytes.Buffer
	read, err := symmetric.DecryptFromFile(key, filePath, bufio.NewWriter(&decrypted))
	assert.NoError(t, err, "We should be able to decrypt this")
	t.Logf("read %d bytes from %s", read, filePath)
	return symmetric.PasswordToKey(decrypted.String(), symmetric.AESKeySize256)
}

func TestStreams(t *testing.T) {
	const (
		encryptedFileName = "encrypted"
		cycledFileName    = "cycled"
	)
	tmpDir, err := os.MkdirTemp("", "StreamsTest")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}

	filePath := filepath.Join(tmpDir, encryptedFileName)
	t.Logf("encrypting to %s", filePath)
	generated := []byte(passwordGen.RandomPassword(1024, passwordGen.AllBytes))
	generatedSha := symmetric.PasswordToKey(string(generated), symmetric.AESKeySize256)
	reader := bufio.NewReader(bytes.NewReader(generated))
	password := []byte(passwordGen.RandomPassword(10, passwordGen.AllBytes))
	key := symmetric.PasswordToKey(string(password), symmetric.AESKeySize256)

	// encryption
	written, err := symmetric.EncryptToFile(key, reader, filePath)
	assert.NoError(t, err, "We should be able to encrypt this")
	assert.FileExists(t, filePath, "EncryptToFile should have created %s", filePath)
	size, err := fileSize(filePath)
	assert.NoError(t, err, "We should be able to read fle size")
	assert.Equal(t, written, size, "written should report same number of bytes as filesize")
	t.Logf("written %d bytes to %s", written, filePath)
	encryptedFileSha, err := fileSha(filePath)
	require.NoError(t, err, "Should be able to get sha from file")
	assert.NotEqual(t, generatedSha, encryptedFileSha, "after encryption, file should have different sha then generated input")

	// decryption
	decryptedSha := decryptShaHelper(t, key, filePath)
	assert.Equal(t, generatedSha, decryptedSha, "after decryption, data should have same sha as generated input")

	t.Log("cycling")
	key2 := symmetric.PasswordToKey(string(password), symmetric.AESKeySize256)
	cycledFilePath := filepath.Join(tmpDir, cycledFileName)
	err = symmetric.Cycle(key, filePath, key2, cycledFilePath)
	assert.NoError(t, err, "cycle should succeed")
	cycledFileSha, err := fileSha(cycledFilePath)
	require.NoError(t, err, "Should be able to get sha from file")
	assert.NotEqual(t, encryptedFileSha, cycledFileSha, "after cycling files should be different")

	decryptedCycledSha := decryptShaHelper(t, key2, cycledFilePath)
	assert.Equal(t, generatedSha, decryptedCycledSha, "after decryption, recycled data should have same sha as generated input")
}

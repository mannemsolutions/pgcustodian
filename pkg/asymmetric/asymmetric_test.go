package asymmetric_test

import (
	"crypto/rsa"
	"fmt"
	"mannemsolutions/pgcustodian/pkg/asymmetric"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	privateKeyFileName  = "private.pem"
	privateKeyFileName2 = "private2.pem"
	publicKeyFileName   = "public.pem"
	encryptedFileName   = "encrypted.bin"
	label               = "asymmetric_test"
)

func TestPrivateKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "Generate")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	defer os.RemoveAll(tmpDir)

	folderWithNoPermissions := path.Join(tmpDir, "noperms")
	err = os.Mkdir(folderWithNoPermissions, 0o000)
	require.NoError(t, err)

	privateFile := path.Join(tmpDir, privateKeyFileName)
	privateKey, err := asymmetric.GeneratePrivateKey(privateFile)
	assert.NoError(t, err, "should be able to generate and write private key")
	assert.NotNil(t, privateKey, "GenPK should return a pointer to a private key")
	data, err := os.ReadFile(privateFile)
	require.NoError(t, err, "should be able to read back the private key")
	privateKeyLines := strings.Split(string(data), "\n")
	require.Len(t, privateKeyLines, 52)
	assert.Equal(t, privateKeyLines[0], "-----BEGIN RSA PRIVATE KEY-----")
	assert.Equal(t, privateKeyLines[len(privateKeyLines)-2], "-----END RSA PRIVATE KEY-----")

	_, err = asymmetric.GeneratePrivateKey(path.Join(folderWithNoPermissions, privateKeyFileName))
	assert.Error(t, err, "without permissions to create the private key file GPK should not be able to write to it and should raise an error")

	_, err = asymmetric.ReadPrivateKeyFromFile("")
	assert.Error(t, err, "ReadPrivateKeyFromFile should raise error when file is empty-string")

	_, err = asymmetric.ReadPrivateKeyFromFile(path.Join(tmpDir, "does_not_exists"))
	assert.Error(t, err, "reading file that does not exist should return an error ")

	_, err = asymmetric.ReadPrivateKeyFromFile("/dev/null")
	assert.Error(t, err, "reading empty file should return an error ")

	privateKey, err = asymmetric.ReadPrivateKeyFromFile(privateFile)
	assert.NoError(t, err, "should be able to read back private key")
	assert.NotNil(t, privateKey, "RPKFF should return a pointer to a private key")

	_, err = asymmetric.PrivateToPublic(&rsa.PrivateKey{}, path.Join(folderWithNoPermissions, "public.pem"))
	assert.Error(t, err, "without permissions to create the public key file P2P should not be able to create it and should raise an error")

	_, err = asymmetric.PrivateToPublic(privateKey, path.Join(folderWithNoPermissions, "public.pem"))
	assert.Error(t, err, "without permissions to create the public key file P2P should not be able to create it and should raise an error")

	publicFile := path.Join(tmpDir, "public.pem")
	publicKey, err := asymmetric.PrivateToPublic(privateKey, publicFile)
	assert.NoError(t, err, "should be able to get public key from private key")
	assert.NotNil(t, publicKey, "P2P should return a pointer to a public key")

	data, err = os.ReadFile(publicFile)
	require.NoError(t, err, "should be able to read back the public key")
	publicKeyLines := strings.Split(string(data), "\n")
	require.Len(t, publicKeyLines, 15)
	assert.Equal(t, publicKeyLines[0], "-----BEGIN RSA PUBLIC KEY-----")
	assert.Equal(t, publicKeyLines[len(publicKeyLines)-2], "-----END RSA PUBLIC KEY-----")

	_, err = asymmetric.PrivateToPublic(privateKey, "")
	assert.NoError(t, err, "without specifying a file name, P2P should not return an error")
	assert.NotNil(t, publicKey, "P2P should return a pointer to a public key")

	_, err = asymmetric.ReadPublicKeyFromFile(path.Join(tmpDir, "does_not_exists"))
	assert.Error(t, err, "reading file that does not exist should return an error ")

}

func TestEncryptDecryptFile(t *testing.T) {

	tmpDir, err := os.MkdirTemp("", "encrypt_decrypt")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	defer os.RemoveAll(tmpDir)

	folderWithNoPermissions := path.Join(tmpDir, "noperms")
	err = os.Mkdir(folderWithNoPermissions, 0o000)
	require.NoError(t, err)

	privateFile := path.Join(tmpDir, privateKeyFileName)
	privateKey, err := asymmetric.GeneratePrivateKey(privateFile)
	require.NoError(t, err, "should be able to generate and write private key")
	require.NotNil(t, privateKey, "GenPK should return a pointer to a private key")

	generated := []byte(passwordGen.RandomPassword(256, passwordGen.AllBytes))
	encryptedFile := path.Join(tmpDir, encryptedFileName)
	err = asymmetric.EncryptToFile(&privateKey.PublicKey, encryptedFile, label, generated)
	assert.FileExists(t, encryptedFile, "should have created file with encrypted data")
	assert.NoError(t, err, "should be able to write encrypted data")

	err = asymmetric.EncryptToFile(&privateKey.PublicKey, path.Join(folderWithNoPermissions, encryptedFileName), label, generated)
	assert.Error(t, err, "trying to write to file without correct permissions should raise error")

	err = asymmetric.EncryptToFile(nil, encryptedFileName, label, generated)
	assert.Error(t, err, "trying to encrypt without key should raise error")

	err = asymmetric.EncryptToFile(&privateKey.PublicKey, "", label, generated)
	assert.Error(t, err, "trying to encrypt to file without specifying path should raise error")

	data, err := os.ReadFile(encryptedFile)
	assert.NoError(t, err, "should be able to read back the public key")
	assert.GreaterOrEqual(t, len(data), len(generated), "encrypted file should not contain the actual data")
	assert.NotContains(t, string(data), string(generated), "encrypted file should not contain the actual data")

	decrypted, err := asymmetric.DecryptFromFile(privateKey, encryptedFile, label)
	assert.NoError(t, err, "decrypting file should succeed")
	assert.Equal(t, generated, decrypted, "after encryption and decryption data should be what we started with")

	_, err = asymmetric.DecryptFromFile(nil, encryptedFile, label)
	assert.Error(t, err, "decrypting without specifying key should raise error")

	privateKey2, err := asymmetric.GeneratePrivateKey(path.Join(tmpDir, privateKeyFileName2))
	require.NoError(t, err)
	_, err = asymmetric.DecryptFromFile(privateKey2, encryptedFile, label)
	assert.Error(t, err, "decrypting with other key should raise error")

	_, err = asymmetric.DecryptFromFile(privateKey, "/dev/null", label)
	assert.Error(t, err, "decrypting empty file should raise error")

	_, err = asymmetric.DecryptFromFile(privateKey, path.Join(folderWithNoPermissions, encryptedFileName), label)
	assert.Error(t, err, "decrypting file we do not have access to should raise error")

	_, err = asymmetric.DecryptFromFile(privateKey, encryptedFile, label+"wrong")
	assert.Error(t, err, "decrypting file with other label should raise an error")
}

func TestEncryptDecrypt(t *testing.T) {
	var decrypted []byte
	var encrypted []byte

	privateKey, err := asymmetric.GeneratePrivateKey("/dev/null")
	require.NoError(t, err)

	decrypted, err = asymmetric.Decrypt(nil, []byte("something"), "")
	assert.Error(t, err)
	assert.Nil(t, decrypted)

	decrypted, err = asymmetric.Decrypt(privateKey, nil, "")
	assert.Error(t, err)
	assert.Nil(t, decrypted)

	encrypted, err = asymmetric.Encrypt(nil, []byte("something"), "")
	assert.Error(t, err)
	assert.Nil(t, encrypted)

	encrypted, err = asymmetric.Encrypt(&privateKey.PublicKey, nil, "")
	assert.Error(t, err)
	assert.Nil(t, encrypted)
}

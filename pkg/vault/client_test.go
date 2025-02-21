package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

var preservedEnv map[string]string

func setEnv(key string, value string) {
	if preservedEnv == nil {
		preservedEnv = make(map[string]string)
	}
	if _, exists := preservedEnv[key]; !exists {
		preservedEnv[key] = os.Getenv(key)
	}
	os.Setenv(key, value)
}

func RestoreEnv() {
	for key, value := range preservedEnv {
		os.Setenv(key, value)
	}
}

func TestStoreVersion(t *testing.T) {
	const (
		v1 uint8 = 1
		v2 uint8 = 2
	)
	defer RestoreEnv()
	setEnv(envStoreVersion, "")
	assert.Equal(t, DefaultStoreVersion, storeVersion(), "when unset we should get the default version")
	setEnv(envStoreVersion, "1")
	assert.Equal(t, v1, storeVersion(), "when set to 1 we should get 1")
	setEnv(envStoreVersion, "0000001")
	assert.Equal(t, v1, storeVersion(), "when set to 0000001 we should get 1")
	setEnv(envStoreVersion, "2")
	assert.Equal(t, v2, storeVersion(), "when set to 2 we should get 2")
	setEnv(envStoreVersion, "0")
	assert.Equal(t, DefaultStoreVersion, storeVersion(), "when set to 0 we should get default value")
	setEnv(envStoreVersion, "3")
	assert.Equal(t, DefaultStoreVersion, storeVersion(), "when set to 3 we should get default value")
	setEnv(envStoreVersion, "3")
	assert.Equal(t, DefaultStoreVersion, storeVersion(), "when set to anything we cannot convert to number we should get default value")
}

func TestNewClientFromEnv(t *testing.T) {
	const (
		roleId             = "roleId"
		secretIdFile       = "/a/b/c/d"
		storeVersion uint8 = 2
	)
	defer RestoreEnv()
	setEnv(envRoleID, roleId)
	setEnv(envSecretIDFile, secretIdFile)
	setEnv(envStoreVersion, string(storeVersion))
	client := NewClient()
	assert.Equal(t, roleId, client.RoleID, fmt.Sprintf("client.RoleID should default to %s", roleId))
	assert.Equal(t, secretIdFile, client.SecretID.FromFile, fmt.Sprintf("client.SecretIDFile should default to %s", secretIdFile))
	assert.Equal(t, false, client.IsWrapped, "client.IsWrapped should default to false")
	assert.Equal(t, storeVersion, client.StoreVersion, fmt.Sprintf("client.StoreVersion should default to %d", storeVersion))
	assert.Equal(
		t,
		DefaultStore(storeVersion),
		client.StorePath,
		fmt.Sprintf("client.StorePath should default to %s", DefaultStore(storeVersion)),
	)
	assert.Equal(t, "", client.token, "client.token should default to emptystring")
}

func TestClientToken(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" {
		return
	}
	const (
		token1 = "token1"
		token2 = "token2"
	)
	client := NewClient()
	client.SetToken(token1)
	assert.Equal(t, token1, client.token, fmt.Sprintf("client.token should be set to %s", token1))
	client.SetToken(token2)
	assert.Equal(t, token1, client.token, "client.token should not be changed by SetToken once set")

	// Create folder
	tmpDir, err := os.MkdirTemp("", "TokenFileTest")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}

	// add file
	filePath := filepath.Join(tmpDir, token2)
	t.Logf("writing %s to file %s", token2, filePath)
	if err := os.WriteFile(filePath, []byte(token2), 0o600); err != nil {
		panic(fmt.Errorf("unable to create %s temp file: %w", filePath, err))
	}
	client.SetTokenFromFile(token2)
	assert.NotEqual(t, token2, client.token, "client.token should not be changed by SetTokenFromFile once set")
	client.token = ""
	client.SetTokenFromFile(filePath)
	assert.Equal(t, token2, client.token, fmt.Sprintf("client.token should be set to %s if unset", token2))

	exportPath := filepath.Join(tmpDir, "exported")
	assert.NoError(t, client.ExportTokenToFile(exportPath), "ExportTokenToFile should not return an error")
	assert.FileExists(t, exportPath, "%s should be created", exportPath)
	dat, err := os.ReadFile(exportPath)
	assert.NoError(t, err, "ExportTokenToFile should be readable")
	assert.Equal(t, token2, string(dat), "exported file should contain token")
}

func TestConnectToken(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" {
		return
	}
	client := NewClient()
	client.SetToken("pgcustodian")
	t.Logf("token: %s", client.token)
	err := client.Connect()
	assert.NoError(t, err, "login to vault should succeed")
	assert.NotEmpty(t, client.token, "After connect with vault, there should be a token")
	assert.NotNil(t, client.client, "After connect with vault, there should be vault client registered")
}

func TestConnectRoleID(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" {
		return
	}
	client := NewClient()
	if client.RoleID == "" {
		return
	}
	client.token = ""
	t.Logf("RoleID: %s", client.RoleID)
	t.Logf("SecretIDFile: %s", client.SecretID.FromFile)
	err := client.Connect()
	assert.NoError(t, err, "login to vault should succeed")
	assert.NotEmpty(t, client.token, "After connect with vault, there should be a token")
	assert.NotNil(t, client.client, "After connect with vault, there should be vault client registered")
}

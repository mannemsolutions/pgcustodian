package vault_test

import (
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/vault"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStores(t *testing.T) {
	var (
		storePath      = passwordGen.RandomPassword(4, passwordGen.LowercaseBytes) + "/"
		kvStoreOptions = &api.MountInput{
			Type:        "kv",
			Description: "key/value store v1",
			Options: map[string]string{
				"version": "1",
			},
		}
	)
	if os.Getenv("VAULT_ADDR") == "" {
		return
	}
	client := vault.NewClient()
	paths, err := client.GetStores()
	assert.Error(t, err, "if client has no auth tokens, GetStores should fail")
	assert.Nil(t, paths, "if client has no auth tokens, GetStores should return nil for paths")
	err = client.EnableSecretStore(storePath, kvStoreOptions)
	assert.Error(t, err, "if client has no auth tokens, EnableSecretStore should fail")
	err = client.DisableSecretStore(storePath)
	assert.Error(t, err, "if client has no auth tokens, EnableSecretStore should fail")

	client.SetToken("pgcustodian")
	err = client.Connect()
	require.NoError(t, err)

	paths, err = client.GetStores()
	assert.NoError(t, err)
	assert.Contains(t, paths, "sys/")
	assert.Contains(t, paths, "secret/")

	err = client.EnableSecretStore(
		storePath,
		kvStoreOptions,
	)
	assert.NoError(t, err)

	paths, err = client.GetStores()
	assert.NoError(t, err)
	assert.Contains(t, paths, storePath)

}

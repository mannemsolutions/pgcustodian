package vault_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetGetPatchSecret(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" {
		return
	}
	const (
		secretPath   = "pgcustodian/setgetpatch"
		key1         = "secret1"
		key2         = "secret2"
		value1       = "password1"
		value2       = "password2"
		patchedValue = "patched"
	)
	for _, version := range []uint8{1, 2} {
		t.Logf("Store Version: %d", version)
		client, err := getAppRoleClient()
		require.NoError(t, err)
		if version == 1 {
			client.StorePath = "kv"
		} else {
			client.StorePath = "secret"
		}
		client.StoreVersion = version
		secrets := map[string]string{
			key1: value1,
			key2: value2,
		}
		err = client.SetSecret(secretPath, secrets)
		assert.NoError(t, err, "Setting a secret should succeed")

		getSecret, err := client.GetSecret(secretPath, key1)
		assert.NoError(t, err, "Getting a secret should succeed")
		assert.Equal(t, value1, getSecret, "Secret should be what was stored")

		patchedSecrets := map[string]string{
			key1: patchedValue,
		}

		err = client.PatchSecret(secretPath, patchedSecrets)
		assert.NoError(t, err, "Patching secret should succeed")

		getPatchedSecret, err := client.GetSecret(secretPath, key1)
		assert.NoError(t, err, "Getting a secret should succeed")
		assert.Equal(t, patchedValue, getPatchedSecret, "Secret should be what was patched")

	}
}

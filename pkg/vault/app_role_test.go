package vault_test

import (
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/vault"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	appRoleName    = passwordGen.RandomPassword(10, passwordGen.LowercaseBytes)
	appRoleOptions = map[string]interface{}{
		"token_type":     "service",
		"token_max_ttl":  "30s",
		"token_num_uses": 10,
	}
)

func TestAutoConnect(t *testing.T) {
	client := vault.Client{}
	err := client.EnableAppRoles()
	assert.Error(t, err, "EnableAppRoles should return error when unable to connect")
	_, err = client.AppRolesEnabled()
	assert.Error(t, err, "AppRolesEnabled should return error when unable to connect")
	err = client.DisableAppRoles()
	assert.Error(t, err, "DisableAppRoles should return error when unable to connect")
	_, err = client.GetAppRoles()
	assert.Error(t, err, "GetAppRoles should return error when unable to connect")
	err = client.AddAppRole(appRoleName, appRoleOptions)
	assert.Error(t, err, "AddAppRole should return error when unable to connect")
	err = client.DeleteAppRole(appRoleName)
	assert.Error(t, err, "AddAppRole should return error when unable to connect")
	_, err = client.GetAppRoleId(appRoleName)
	assert.Error(t, err, "GetAppRoleId should return error when unable to connect")
	_, err = client.GetSecretId(appRoleName)
	assert.Error(t, err, "GetSecretId should return error when unable to connect")

}
func TestDisableAppRoles(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" {
		return
	}
	client := getRootClient()

	enabled, err := client.AppRolesEnabled()
	require.NoError(t, err)
	t.Logf("AppRoles enabled: %t", enabled)
	err = client.EnableAppRoles()
	require.NoError(t, err)

	enabled, err = client.AppRolesEnabled()
	require.NoError(t, err)
	require.True(t, enabled, "AppRoles should now be enabled")

	err = client.DisableAppRoles()
	assert.NoError(t, err)

	enabled, err = client.AppRolesEnabled()
	require.NoError(t, err)
	assert.False(t, enabled, "AppRolesEnabled should now return false")

	err = client.DisableAppRoles()
	assert.NoError(t, err, "Disabling AppRoles a second time should be ok")

	err = client.EnableAppRoles()
	assert.NoError(t, err)
	enabled, err = client.AppRolesEnabled()
	assert.NoError(t, err)
	assert.True(t, enabled, "AppRoles should now be enabled")
	err = client.EnableAppRoles()
	assert.NoError(t, err, "Enabling AppRoles when already enabled, should be ok")
}

func TestAppRolesCRUD(t *testing.T) {

	if os.Getenv("VAULT_ADDR") == "" {
		return
	}
	client := getRootClient()
	err := client.EnableAppRoles()
	require.NoError(t, err)

	enabled, err := client.AppRolesEnabled()
	require.NoError(t, err)
	require.True(t, enabled, "AppRoles should now be enabled")

	err = client.AddAppRole(appRoleName, appRoleOptions)
	assert.NoError(t, err)

	appRoleId, err := client.GetAppRoleId(appRoleName)
	assert.NoError(t, err)
	assert.Regexp(t, `^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`, appRoleId)

	secretId, err := client.GetSecretId(appRoleName)
	assert.NoError(t, err)
	assert.Regexp(t, `^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`, secretId)

	responseData, err := client.GetAppRoles()
	assert.NoError(t, err)
	t.Logf("%v", responseData)
	assert.Contains(t, responseData, appRoleName)

	err = client.DeleteAppRole(appRoleName)
	assert.NoError(t, err)
	// responseData, err = client.GetAppRoles()
	// assert.NoError(t, err)
	// assert.Contains(t, responseData, appRoleName)
}

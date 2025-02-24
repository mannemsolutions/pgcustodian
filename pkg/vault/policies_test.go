package vault_test

import (
	"os"
	"testing"

	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicies(t *testing.T) {
	var (
		policyName  = passwordGen.RandomPassword(10, passwordGen.LowercaseBytes)
		policyRules = `path "secret/foo" {
  capabilities = ["read"]
}`
	)
	if os.Getenv("VAULT_ADDR") == "" {
		return
	}
	client := vault.NewClient()
	client.SetToken("pgcustodian")
	err := client.Connect()
	require.NoError(t, err)

	err = client.CreatePolicy(policyName, policyRules)
	assert.NoError(t, err)

	policies, err := client.GetPolicies()
	assert.NoError(t, err)
	assert.Contains(t, policies, "default")
	assert.Contains(t, policies, "root")
	assert.Contains(t, policies, policyName)

	err = client.DeletePolicy(policyName)
	assert.NoError(t, err)

	policies, err = client.GetPolicies()
	assert.NoError(t, err)
	assert.Contains(t, policies, "default")
	assert.Contains(t, policies, "root")
	assert.NotContains(t, policies, policyName)
}

package vault_test

import (
	"fmt"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/vault"
	"os"

	"github.com/hashicorp/vault/api"
)

const (
	rootTokenEnvVar = "PGC_TEST_ROOT_TOKEN"
	policyName      = "unittest_policy"
	policyRules     = `path "kv/pgcustodian/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "secret/data/pgcustodian/*" {
  capabilities = ["create", "update", "patch", "read", "delete"]
}


path "secret/metadata/pgcustodian/*" {
  capabilities = ["list"]
}`
)

var (
	appRoleClient *vault.Client
	rootClient    *vault.Client
)

func getRootClient() *vault.Client {
	if rootClient != nil {
		return rootClient
	}
	client := vault.NewClient()
	client.SetToken(os.Getenv(rootTokenEnvVar))
	err := client.Connect()
	if err != nil {
		panic("could not get root connection to vault")
	}
	rootClient = client
	return client
}

func getAppRoleClient() (*vault.Client, error) {
	if appRoleClient != nil {
		return appRoleClient, nil
	}

	var appRoleName = passwordGen.RandomPassword(10, passwordGen.LowercaseBytes)

	myRootClient := getRootClient()
	err := myRootClient.EnableSecretStore(
		"kv/",
		&api.MountInput{
			Type:        "kv",
			Description: "key/value store v1",
			Options: map[string]string{
				"version": "1",
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("could not enable secret store %w", err)
	}
	err = myRootClient.EnableAppRoles()
	if err != nil {
		return nil, fmt.Errorf("could not get root connection to vault: %w", err)
	}
	policies, err := myRootClient.GetPolicies()
	if err != nil {
		return nil, fmt.Errorf("could not get policies: %w", err)
	}
	if _, exists := policies[policyName]; !exists {
		err = myRootClient.CreatePolicy(policyName, policyRules)
		if err != nil {
			return nil, fmt.Errorf("could not create policy: %w", err)
		}
	}
	err = myRootClient.AddAppRole(
		appRoleName,
		map[string]interface{}{
			"token_type":     "service",
			"token_max_ttl":  "30s",
			"token_num_uses": "10",
			"policies":       policyName,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("could not create app-role: %w", err)
	}
	appRoleId, err := myRootClient.GetAppRoleId(appRoleName)
	if err != nil {
		return nil, fmt.Errorf("could not get app-role-id: %w", err)
	}
	secretId, err := myRootClient.GetSecretId(appRoleName)
	if err != nil {
		return nil, fmt.Errorf("could not get secret-id: %w", err)
	}

	client := vault.NewClient()
	client.RoleID = appRoleId
	client.SecretID.FromString = secretId
	client.SecretID.FromFile = ""
	err = client.Connect()
	if err != nil {
		return nil, fmt.Errorf("could not get client connection to vault: %w", err)
	}
	appRoleClient = client
	return client, nil
}

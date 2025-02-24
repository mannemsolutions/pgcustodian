package main

import (
	"mannemsolutions/pgcustodian/pkg/utils"
	"os"
	"path"

	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	policyName         = "pgcustodian"
	customPolicyFile   = "~/.pgcustodian/custom_policy.hcl"
	customPolicyEnvVar = "PGC_CUSTOM_POLICY_FILE"
	roleNameEnvVar     = "PGC_ROLE_NAME"
	roleIdFileEnvVar   = "PGC_ROLE_ID_FILE"
	defaultPermissions = 0o600

	defaultPolicyRules = `path "kv/pgcustodian/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "secret/data/pgcustodian/*" {
  capabilities = ["create", "update", "patch", "read", "delete"]
}


path "secret/metadata/pgcustodian/*" {
  capabilities = ["list"]
}`
)

func stageCommand() *cobra.Command {
	stageCommand := &cobra.Command{
		Use:   "stage",
		Short: "stage hashicorp vault for pgcustodian usage",
		Long:  `Use this command to setup hashicorp vault so that it is ready to be used by pgcustodian.`,
		Run: func(cmd *cobra.Command, args []string) {

			setVerbosity(viper.GetInt("verbose"))

			//retrieve password from vault
			client := setupClient()
			if client.StoreVersion == 1 {
				err := client.EnableSecretStore(client.StorePath+"/",
					&api.MountInput{
						Type:        "kv",
						Description: "key/value store v1",
						Options: map[string]string{
							"version": "1",
						},
					})
				if err != nil {
					log.Panicf("enabling v1 kv store failed: %w", err)
				}
				log.Info("enabling kv1 store succeeded")
			}

			policyRules := defaultPolicyRules
			data, err := os.ReadFile(utils.ResolveHome(viper.GetString(customPolicyFile)))
			if err == nil {
				policyRules = string(data)
			}
			err = client.CreatePolicy(policyName, policyRules)
			if err != nil {
				log.Panicf("creating policy %s failed: %w", policyName, err)
			}
			log.Infof("creating policy %s succeeded", policyName)

			err = client.EnableAppRoles()
			if err != nil {
				log.Panicf("enabling app-roles failed: %w", err)
			}
			log.Info("enabling app-roles succeeded")

			appRoleName := viper.GetString("roleName")
			err = client.AddAppRole(
				appRoleName,
				map[string]interface{}{
					"token_type":     "service",
					"token_max_ttl":  "30s",
					"token_num_uses": "10",
					"policies":       policyName,
				},
			)
			if err != nil {
				log.Panicf("creating app-role %s failed: %w", appRoleName, err)
			}
			log.Infof("creating app-role %s succeeded", appRoleName)

			roleIdFile := utils.ResolveHome(viper.GetString("roleIdFile"))
			roleIdDir := path.Dir(roleIdFile)
			err = utils.MakeTree(roleIdDir)
			if err != nil {
				log.Panicf("creating directory for role-id %s failed: %w", roleIdDir, err)
			}
			log.Infof("creating directory for role-id %s succeeded", roleIdDir)

			roleName := viper.GetString("roleName")
			roleId, err := client.GetAppRoleId(roleName)
			if err != nil {
				log.Panicf("retrieving app-role-id for %s failed: %w", roleName, err)
			}
			err = os.WriteFile(roleIdFile, []byte(roleId), defaultPermissions)
			if err != nil {
				log.Panicf("writing role-id for %s to %s failed: %w", roleName, roleIdFile, err)
			}
			log.Infof("role-id for %s successfully written to %s", roleName, roleIdFile)

			secretIdFile := utils.ResolveHome(viper.GetString("secretIdFile"))
			secretIdDir := path.Dir(secretIdFile)
			err = utils.MakeTree(secretIdDir)
			if err != nil {
				log.Panicf("creating directory for secret-id %s failed: %w", secretIdDir, err)
			}
			log.Infof("creating directory for secret-id %s succeeded", secretIdDir)
			secretID, err := client.GetSecretId(viper.GetString("roleName"))
			if err != nil {
				log.Panicf("retrieving secret-id for %s failed: %w", roleName, err)
			}
			err = os.WriteFile(secretIdFile, []byte(secretID), defaultPermissions)
			if err != nil {
				log.Panicf("writing secret-id for %s to file %s failed: %w", roleName, secretIdFile, err)
			}
			log.Infof("secret-id for %s successfully written to %s", roleName, secretIdFile)
		},
	}

	stageCommand.PersistentFlags().StringP("customPolicyFile", "C", customPolicyFile,
		`File with custom policy to be applied 
		(defaults allow on kv/pgcustodian, secret/data/pgcustodian and secret/metadata/pgcustodian).`)
	bindArgument("", "customPolicyFile", stageCommand, []string{customPolicyEnvVar}, customPolicyFile)

	hostName, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	stageCommand.PersistentFlags().StringP("roleName", "n", hostName,
		`Role name to be used.`)
	bindArgument("", "roleName", stageCommand, []string{roleNameEnvVar}, hostName)

	return stageCommand
}

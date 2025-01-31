package main

// Implementation of the "add" sub command.

import (
	"mannemsolutions/pgcustodian/pkg/crypt"
	"mannemsolutions/pgcustodian/pkg/vault"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/*
decrypt (pg_ctl start):
  env:
    file path
	key path
	vault token
  stdout: pg generated something from generate
*/

func loginCommand() *cobra.Command {
	loginCommand := &cobra.Command{
		Use:   "login",
		Short: "login and generate token",
		Long: `Use this command to login to Vault and generate a onetime token.
		This command can be run by a high privileged user, and the resulting token 
		can be delivered to the low privileged user for onetime authentication,
		thus resulting in separation between credentials and service utilizing the key.`,
		Run: func(cmd *cobra.Command, args []string) {
			enableDebug(viper.GetInt("verbose") > 0)
			client := vault.NewClient()
			client.IsWrapped = viper.GetBool("wrapped")
			client.RoleID = viper.GetString("roleid")
			client.SecretIDFile = viper.GetString("secretIdFile")
			tokenFile := viper.GetString("tokenFile")
			if err := client.ExportTokenToFile(tokenFile); err != nil {
				log.Panicf("failed to export auth token: %w", err)
			}

		},
	}
	loginCommand.PersistentFlags().StringP("tokenFile", "T", "~/.vault/token",
		`tokenFile can be set to a path containing the token for logging into vault.
		If token is set, tokenFile is unused.
		If either tokenFile or token are set, roleId and secretId are unused.
		Defaults are derived from PGC_TOKEN_FILE, and VAULT_TOKE_FILE in that order.`)
	bindArgument("", "token", loginCommand, []string{"PGC_TOKEN_FILE", "VAULT_TOKEN_FILE"}, "~/.vault/token")

	loginCommand.PersistentFlags().StringP("token", "t", "",
		`token for logging into vault.
		If token is set, roleId and secretId are unused.
		Defaults are derived from PGC_TOKEN, and VAULT_TOKEN in that order.`)
	bindArgument("", "token", loginCommand, []string{"PGC_TOKEN", "VAULT_TOKEN"}, "")

	loginCommand.PersistentFlags().StringP("roleId", "r", "",
		`role id for logging into vault.
		Defaults are derived from PGC_ROLE_ID.`)
	bindArgument("", "roleId", loginCommand, []string{"PGC_ROLE_ID"}, "")

	loginCommand.PersistentFlags().StringP("secretIdFile", "s", "",
		`secret id for logging into vault.
		Defaults are derived from PGC_SECRET_ID_FILE.`)
	bindArgument("", "secretIdFile", loginCommand, []string{"PGC_SECRET_ID_FILE"}, "")

	loginCommand.PersistentFlags().Uint8P("storeVersion", "v", 2,
		`version of vault store.`)
	bindArgument("", "storeVersion", loginCommand, []string{"PGC_STORE_VERSION"}, 2)

	loginCommand.PersistentFlags().StringP("storePath", "p", "",
		`path to kv1 or kv2 store where secrets are held.`)
	bindArgument("", "storePath", loginCommand, []string{"PGC_STORE_PATH"}, "")

	loginCommand.PersistentFlags().StringP("secretPath", "P", "",
		`path in kv1 or kv2 store where secrets are held.`)
	bindArgument("", "secretPath", loginCommand, []string{"PGC_SECRET_PATH"}, "")

	loginCommand.PersistentFlags().StringP("secretKey", "k", "",
		`path in kv1 or kv2 store where secrets are held.`)
	bindArgument("", "secretKey", loginCommand, []string{"PGC_SECRET_KEY"}, "")

	loginCommand.PersistentFlags().StringP("encryptedFile", "f", "",
		`path to file with decrypted version of data.`)
	bindArgument("", "encryptedFile", loginCommand, []string{"PGC_ENCRYPTED_FILE"}, "")

	var keySize crypt.AESKeyEnum = crypt.AESKeyEnum256
	loginCommand.PersistentFlags().VarP(&keySize, "aesKeySize", "a", `key size for AES decryption.`)
	bindArgument("", "aesKeySize", loginCommand, []string{"PGC_AES_KEY_SIZE"}, 16)

	return loginCommand
}

package main

// Implementation of the "add" sub command.

import (
	"bufio"
	"mannemsolutions/pgcustodian/pkg/crypt"
	"mannemsolutions/pgcustodian/pkg/vault"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/*
export (pg_ctl start):
  env:
    file path
	key path
	vault token
  stdout: pg generated something from generate
*/

func exportCommand() *cobra.Command {
	exportCommand := &cobra.Command{
		Use:   "export",
		Short: "export key to asymmetrically encrypted file",
		Long: `Use this command to export the key to an encrypted file for backup purposes.
		Intention is not to `,
		Run: func(cmd *cobra.Command, args []string) {
			enableDebug(viper.GetInt("verbose") > 0)
			inFile := viper.GetString("encryptedFile")
			client := vault.NewClient()
			client.IsWrapped = viper.GetBool("wrapped")
			client.RoleID = viper.GetString("roleid")
			client.SecretIDFile = viper.GetString("secretIdFile")
			client.StorePath = viper.GetString("storePath")
			client.StoreVersion = uint8(viper.GetUint("storeVersion"))
			client.SetToken(viper.GetString("token"))
			client.SetTokenFromFile(viper.GetString("tokenFile"))

			var generatedPassword string
			var err error
			secretKey := viper.GetString("secretKey")
			secretPath := viper.GetString("secretPath")
			if generatedPassword, err = client.GetSecret(secretPath, secretKey); err != nil {
				log.Panicf("failed to get secret from vault: %w", err)
			}
			exportionKey := crypt.PasswordToKey(generatedPassword, crypt.AESKeySize256)
			if read, err := crypt.DecryptFromFile(exportionKey, inFile, bufio.NewWriter(os.Stdout)); err != nil {
				log.Panicf("failed to export file %s with secret from vault: %w", err)
			} else {
				log.Infof("succesfully read %d bytes of data from file %s, decrypted with secret from vault and written to stdout", read, inFile)
			}
		},
	}
	exportCommand.PersistentFlags().StringP("tokenFile", "T", "~/.vault/token",
		`tokenFile can be set to a path containing the token for logging into vault.
		If token is set, tokenFile is unused.
		If either tokenFile or token are set, roleId and secretId are unused.
		Defaults are derived from PGC_TOKEN_FILE, and VAULT_TOKE_FILE in that order.`)
	bindArgument("", "token", exportCommand, []string{"PGC_TOKEN_FILE", "VAULT_TOKEN_FILE"}, "~/.vault/token")

	exportCommand.PersistentFlags().StringP("token", "t", "",
		`token for logging into vault.
		If token is set, roleId and secretId are unused.
		Defaults are derived from PGC_TOKEN, and VAULT_TOKEN in that order.`)
	bindArgument("", "token", exportCommand, []string{"PGC_TOKEN", "VAULT_TOKEN"}, "")

	exportCommand.PersistentFlags().StringP("roleId", "r", "",
		`role id for logging into vault.
		Defaults are derived from PGC_ROLE_ID.`)
	bindArgument("", "roleId", exportCommand, []string{"PGC_ROLE_ID"}, "")

	exportCommand.PersistentFlags().StringP("secretIdFile", "s", "",
		`secret id for logging into vault.
		Defaults are derived from PGC_SECRET_ID_FILE.`)
	bindArgument("", "secretIdFile", exportCommand, []string{"PGC_SECRET_ID_FILE"}, "")

	exportCommand.PersistentFlags().Uint8P("storeVersion", "v", 2,
		`version of vault store.`)
	bindArgument("", "storeVersion", exportCommand, []string{"PGC_STORE_VERSION"}, 2)

	exportCommand.PersistentFlags().StringP("storePath", "p", "",
		`path to kv1 or kv2 store where secrets are held.`)
	bindArgument("", "storePath", exportCommand, []string{"PGC_STORE_PATH"}, "")

	exportCommand.PersistentFlags().StringP("secretPath", "P", "",
		`path in kv1 or kv2 store where secrets are held.`)
	bindArgument("", "secretPath", exportCommand, []string{"PGC_SECRET_PATH"}, "")

	exportCommand.PersistentFlags().StringP("secretKey", "k", "",
		`path in kv1 or kv2 store where secrets are held.`)
	bindArgument("", "secretKey", exportCommand, []string{"PGC_SECRET_KEY"}, "")

	exportCommand.PersistentFlags().StringP("encryptedFile", "f", "",
		`path to file with exported version of data.`)
	bindArgument("", "encryptedFile", exportCommand, []string{"PGC_ENCRYPTED_FILE"}, "")

	var keySize crypt.AESKeyEnum = crypt.AESKeyEnum256
	exportCommand.PersistentFlags().VarP(&keySize, "aesKeySize", "a", `key size for AES exportion.`)
	bindArgument("", "aesKeySize", exportCommand, []string{"PGC_AES_KEY_SIZE"}, 16)

	return exportCommand
}

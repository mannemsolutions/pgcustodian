package main

// Implementation of the "add" sub command.

import (
	"bufio"
	"mannemsolutions/pgcustodian/pkg/crypt"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/vault"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/*
encrypt (initdb):
  stdin: pg generated something
  env:
    file path
	key path
	vault token
  function: generate key and write to vault, encrypt stdin with key and write to file
decrypt (pg_ctl start):
  env:
    file path
	key path
	vault token
  stdout: pg generated something from generate
cycle:
  in: file, key
  out: new file, new key
login:
  env:
    approleid
	appsecretidpath
  out: short lived token
export:
*/

func encryptCommand() *cobra.Command {
	encryptCommand := &cobra.Command{
		Use:   "encrypt",
		Short: "encrypt stdin write to file",
		Long: `Use this command to read from stdin, encrypt and write to a file.
		  (If no key exists in vault, it will be generated and written before using it.)`,
		Run: func(cmd *cobra.Command, args []string) {
			enableDebug(viper.GetInt("verbose") > 0)
			outFile := viper.GetString("encryptedFile")
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
				generatedPassword = passwordGen.RandomPassword(
					viper.GetUint("generatedPasswordLength"),
					viper.GetString("defaultPasswordChars"),
				)
				data := map[string]string{
					secretKey: generatedPassword,
				}
				if err = client.PatchSecret(secretPath, data); err != nil {
					log.Errorf("unable to patch generated key: %w", err)
					return
				}
			}
			encryptionKey := crypt.PasswordToKey(generatedPassword, crypt.AESKeySize256)
			if written, err := crypt.EncryptToFile(encryptionKey, bufio.NewReader(os.Stdin), outFile); err != nil {
				log.Panicf("failed to encrypt file %s with secret from vault: %w", err)
			} else {
				log.Infof("succesfully encrypted data from stdin with secret from vault and written %d bytes to %s", written, outFile)
			}
		},
	}
	encryptCommand.PersistentFlags().StringP("tokenFile", "T", "~/.vault/token",
		`tokenFile can be set to a path containing the token for logging into vault.
		If token is set, tokenFile is unused.
		If either tokenFile or token are set, roleId and secretId are unused.
		Defaults are derived from PGC_TOKEN_FILE, and VAULT_TOKE_FILE in that order.`)
	bindArgument("", "token", encryptCommand, []string{"PGC_TOKEN_FILE", "VAULT_TOKEN_FILE"}, "~/.vault/token")

	encryptCommand.PersistentFlags().StringP("token", "t", "",
		`token for logging into vault.
		If token is set, roleId and secretId are unused.
		Defaults are derived from PGC_TOKEN, and VAULT_TOKEN in that order.`)
	bindArgument("", "token", encryptCommand, []string{"PGC_TOKEN", "VAULT_TOKEN"}, "")

	encryptCommand.PersistentFlags().StringP("roleId", "r", "",
		`role id for logging into vault.
		Defaults are derived from PGC_ROLE_ID.`)
	bindArgument("", "roleId", encryptCommand, []string{"PGC_ROLE_ID"}, "")

	encryptCommand.PersistentFlags().StringP("secretIdFile", "s", "",
		`secret id for logging into vault.
		Defaults are derived from PGC_SECRET_ID_FILE.`)
	bindArgument("", "secretIdFile", encryptCommand, []string{"PGC_SECRET_ID_FILE"}, "")

	encryptCommand.PersistentFlags().Uint8P("storeVersion", "v", 2,
		`version of vault store.`)
	bindArgument("", "storeVersion", encryptCommand, []string{"PGC_STORE_VERSION"}, 2)

	encryptCommand.PersistentFlags().StringP("storePath", "p", "",
		`path to kv1 or kv2 store where secrets are held.`)
	bindArgument("", "storePath", encryptCommand, []string{"PGC_STORE_PATH"}, "")

	encryptCommand.PersistentFlags().StringP("secretPath", "P", "",
		`path in kv1 or kv2 store where secrets are held.`)
	bindArgument("", "secretPath", encryptCommand, []string{"PGC_SECRET_PATH"}, "")

	encryptCommand.PersistentFlags().StringP("secretKey", "k", "",
		`path in kv1 or kv2 store where secrets are held.`)
	bindArgument("", "secretKey", encryptCommand, []string{"PGC_SECRET_KEY"}, "")

	encryptCommand.PersistentFlags().StringP("encryptedFile", "f", "",
		`path to file with encrypted version of data.`)
	bindArgument("", "encryptedFile", encryptCommand, []string{"PGC_ENCRYPTED_FILE"}, "")

	encryptCommand.PersistentFlags().IntP("generatedPasswordLength", "l", 16,
		`length for generated passwords.`)
	bindArgument("", "generatedPasswordLength", encryptCommand, []string{"PGC_GENERATED_PASSWORD_LENGTH"}, 16)

	encryptCommand.PersistentFlags().IntP("generatedPasswordChars", passwordGen.AllBytes, 16,
		`character list for generating passwords.`)
	bindArgument("", "generatedPasswordLength", encryptCommand, []string{"PGC_GENERATED_PASSWORD_LENGTH"}, 16)

	var keySize crypt.AESKeyEnum = crypt.AESKeyEnum256
	encryptCommand.PersistentFlags().VarP(&keySize, "aesKeySize", "a", `key size for AES encryption.`)
	bindArgument("", "aesKeySize", encryptCommand, []string{"PGC_AES_KEY_SIZE"}, 16)

	return encryptCommand
}

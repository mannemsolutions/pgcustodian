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
					viper.GetString("generatedPasswordChars"),
				)
				data := map[string]string{
					secretKey: generatedPassword,
				}
				if err = client.PatchSecret(secretPath, data); err != nil {
					log.Errorf("unable to patch generated key: %w", err)
					return
				}
			}
			encryptionKey := crypt.PasswordToKey(generatedPassword, keySize.ToAESKeySize())
			if written, err := crypt.EncryptToFile(encryptionKey, bufio.NewReader(os.Stdin), outFile); err != nil {
				log.Panicf("failed to encrypt file %s with secret from vault: %w", err)
			} else {
				log.Infof("succesfully encrypted data from stdin with secret from vault and written %d bytes to %s", written, outFile)
			}
		},
	}

	encryptCommand.PersistentFlags().IntP("generatedPasswordLength", "l", 16,
		`length for generated passwords.`)
	bindArgument("", "generatedPasswordLength", encryptCommand, []string{"PGC_GENERATED_PASSWORD_LENGTH"}, 16)

	encryptCommand.PersistentFlags().StringP("generatedPasswordChars", "C", passwordGen.AllBytes,
		`character list for generating passwords.`)
	bindArgument("", "generatedPasswordChars", encryptCommand, []string{"PGC_GENERATED_PASSWORD_LENGTH"}, 16)

	return encryptCommand
}

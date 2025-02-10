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
decrypt (pg_ctl start):
  env:
    file path
	key path
	vault token
  stdout: pg generated something from generate
*/

func decryptCommand() *cobra.Command {
	decryptCommand := &cobra.Command{
		Use:   "decrypt",
		Short: "decrypt file to stdout",
		Long:  `Use this command to read from file, decrypt and write to a stdout.`,
		Run: func(cmd *cobra.Command, args []string) {
			setVerbosity(viper.GetInt("verbose"))
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
			decryptionKey := crypt.PasswordToKey(generatedPassword, keySize.ToAESKeySize())
			if read, err := crypt.DecryptFromFile(decryptionKey, inFile, bufio.NewWriter(os.Stdout)); err != nil {
				log.Panicf("failed to decrypt file %s with secret from vault: %w", err)
			} else {
				log.Infof("succesfully read %d bytes of data from file %s, decrypted with secret from vault and written to stdout", read, inFile)
			}
		},
	}

	return decryptCommand
}

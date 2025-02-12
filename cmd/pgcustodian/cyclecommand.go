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

func cycleCommand() *cobra.Command {
	cycleCommand := &cobra.Command{
		Use:   "cycle",
		Short: "cycle encryption key and file",
		Long:  `Use this command to generate a new key/file from previous key/file.`,
		Run: func(cmd *cobra.Command, args []string) {
			setVerbosity(viper.GetInt("verbose"))
			log.Panic("we need to thoroughly think through the cycling part")
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

	return cycleCommand
}

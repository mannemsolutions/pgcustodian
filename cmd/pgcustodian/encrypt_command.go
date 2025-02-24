package main

import (
	"bufio"
	"mannemsolutions/pgcustodian/pkg/asymmetric"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/symmetric"
	"mannemsolutions/pgcustodian/pkg/utils"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func encryptCommand() *cobra.Command {
	encryptCommand := &cobra.Command{
		Use:   "encrypt",
		Short: "encrypt stdin write to file",
		Long: `Use this command to read from stdin, encrypt and write to a file.
(If no key exists in vault, it will be generated and written before using it.)`,
		Run: func(cmd *cobra.Command, args []string) {
			setVerbosity(viper.GetInt("verbose"))
			encryptedFile := utils.ResolveHome(viper.GetString("encryptedFile"))
			if encryptedFile == "" {
				log.Panic("parameter encryptedFile is mandatory for encrypt")
			}
			client := setupClient()

			var password string
			var err error
			secretKey := viper.GetString("secretKey")
			secretPath := viper.GetString("secretPath")
			if password, err = client.GetSecret(secretPath, secretKey); err != nil {
				password = passwordGen.RandomPassword(
					viper.GetUint("generatedPasswordLength"),
					viper.GetString("generatedPasswordChars"),
				)
				data := map[string]string{
					secretKey: password,
				}
				if err = client.PatchSecret(secretPath, data); err != nil {
					log.Panicf("unable to patch generated key: %w", err)
				}
			}
			publicKeyPath := utils.ResolveHome(viper.GetString("publicKey"))
			backupFilePath := utils.ResolveHome(viper.GetString("backupFile"))
			if backupFilePath == "" {
				log.Info("backup and restore of passwords is disabled")
			} else if key, err := asymmetric.ReadPublicKeyFromFile(publicKeyPath); err != nil {
				log.Errorf("password backup feature failed to read private key: %w", err)
			} else if err = asymmetric.EncryptToFile(key, backupFilePath, encryptedFile, []byte(password)); err != nil {
				log.Errorf("password backup feature failed to write backup file: %w", err)
			}
			log.Infof("password is encrypted with public key and written to %s", backupFilePath)

			encryptionKey := symmetric.PasswordToKey(password, keySize.ToAESKeySize())
			written, err := symmetric.EncryptToFile(encryptionKey, bufio.NewReader(os.Stdin), encryptedFile)
			if err != nil {
				log.Panicf("failed to encrypt file %s with secret from vault: %w", err)
			}
			log.Infof("successfully encrypted data from stdin with secret from vault and written %d bytes to %s", written, encryptedFile)
		},
	}

	encryptCommand.PersistentFlags().IntP("generatedPasswordLength", "l", 16,
		`length for generated passwords.`)
	bindArgument("", "generatedPasswordLength", encryptCommand, []string{"PGC_GENERATED_PASSWORD_LENGTH"}, 16)

	encryptCommand.PersistentFlags().StringP("generatedPasswordChars", "C", passwordGen.AllBytes,
		`character list for generating passwords.`)
	bindArgument("", "generatedPasswordChars", encryptCommand, []string{"PGC_GENERATED_PASSWORD_CHARS"}, 16)

	return encryptCommand
}

package main

import (
	"bufio"
	"mannemsolutions/pgcustodian/pkg/asymmetric"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/symmetric"
	"os"

	"github.com/spf13/cobra"
)

func encryptCommand() *cobra.Command {
	var encryptArgs args
	encryptCommand := &cobra.Command{
		Use:   "encrypt",
		Short: "encrypt stdin write to file",
		Long: `Use this command to read from stdin, encrypt and write to a file.
(If no key exists in vault, it will be generated and written before using it.)`,
		Run: func(cmd *cobra.Command, args []string) {
			setVerbosity(encryptArgs.GetInt("verbose"))
			encryptedFile := encryptArgs.GetString("encryptedFile")
			if encryptedFile == "" {
				log.Panic("parameter encryptedFile is mandatory for encrypt")
			}
			client := encryptArgs.GetClient()

			var password string
			var err error
			secretKey := encryptArgs.GetString("secretKey")
			secretPath := encryptArgs.GetString("secretPath")
			if password, err = client.GetSecret(secretPath, secretKey); err != nil {
				password = passwordGen.RandomPassword(
					encryptArgs.GetUint("generatedPasswordLength"),
					encryptArgs.GetString("generatedPasswordChars"),
				)
				data := map[string]string{
					secretKey: password,
				}
				if err = client.PatchSecret(secretPath, data); err != nil {
					log.Panicf("unable to patch generated key: %w", err)
				}
			}
			publicKeyPath := encryptArgs.GetString("publicKeyPath")
			backupFilePath := encryptArgs.GetString("backupFile")
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
	encryptArgs = allArgs.commandArgs(encryptCommand, append(globalArgs,
		"backupFile",
		"encryptedFile",
		"generatedPasswordChars",
		"generatedPasswordLength",
		"publicKeyPath",
		"secretKey",
		"secretPath",
	))
	return encryptCommand
}

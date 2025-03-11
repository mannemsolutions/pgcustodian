package main

import (
	"bufio"
	"fmt"
	"mannemsolutions/pgcustodian/pkg/asymmetric"
	"mannemsolutions/pgcustodian/pkg/symmetric"
	"os"

	"github.com/spf13/cobra"
)

func usePrivateKey(decryptArgs args) (string, error) {
	privateKeyPath := decryptArgs.GetString("privateKeyPath")
	if privateKeyPath == "" {
		return "", fmt.Errorf("no private key, I don't know the password and cannot decrypt the file")
	}
	if key, err := asymmetric.ReadPrivateKeyFromFile(privateKeyPath); err != nil {
		return "", fmt.Errorf("reading private key failed, I don't know the password and cannot decrypt the file")
	} else if decryptedPassword, err := asymmetric.DecryptFromFile(
		key,
		decryptArgs.GetString("backupFile"),
		decryptArgs.GetString("encryptedFile"),
	); err != nil {
		return "", fmt.Errorf("decrypting password from backupfile failed, I don't know the password and cannot decrypt the file")
	} else {
		log.Infof("falling back to backup file")
		return string(decryptedPassword), nil
	}

}

func decryptCommand() *cobra.Command {
	var decryptArgs args
	decryptCommand := &cobra.Command{
		Use:   "decrypt",
		Short: "decrypt file to stdout",
		Long:  `Use this command to read from file, decrypt and write to a stdout.`,
		Run: func(cmd *cobra.Command, args []string) {
			var password string
			setVerbosity(decryptArgs.GetInt("verbose"))
			encryptedFile := decryptArgs.GetString("encryptedFile")
			if encryptedFile == "" {
				log.Panic("parameter encryptedFile is mandatory for decrypt")
			}
			client := decryptArgs.GetClient()
			secretKey := decryptArgs.GetString("secretKey")
			secretPath := decryptArgs.GetString("secretPath")
			if err := client.Connect(); err != nil {
				log.Errorf("connecting to Vault failed")
				if password, err = usePrivateKey(decryptArgs); err != nil {
					log.Panic(err)
				}
			} else if password, err = client.GetSecret(secretPath, secretKey); err != nil {
				log.Errorf("retrieval from vault Vault failed: %w", err)
				if password, err = usePrivateKey(decryptArgs); err != nil {
					log.Panic(err)
				}
				data := map[string]string{
					secretKey: password,
				}
				if err = client.PatchSecret(secretPath, data); err != nil {
					// as long as we have reported errors, it is still ok to open Postgres
					log.Errorf("unable to write key to vault: %w", err)
				}
			}

			decryptionKey := symmetric.PasswordToKey(password, keySize.ToAESKeySize())
			if read, err := symmetric.DecryptFromFile(decryptionKey, encryptedFile, bufio.NewWriter(os.Stdout)); err != nil {
				log.Panicf("failed to decrypt file %s: %w", err)
			} else {
				log.Infof("successfully read %d bytes of data from file %s, decrypted and written to stdout", read, encryptedFile)
			}
		},
	}

	decryptArgs = allArgs.commandArgs(decryptCommand, append(globalArgs,
		"backupFile",
		"encryptedFile",
		"privateKeyPath",
		"secretKey",
		"secretPath",
	))
	return decryptCommand
}

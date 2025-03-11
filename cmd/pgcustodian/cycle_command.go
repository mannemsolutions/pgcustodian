package main

import (
	"mannemsolutions/pgcustodian/pkg/asymmetric"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/shred"
	"mannemsolutions/pgcustodian/pkg/symmetric"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	privateKeyFileName        = "private.pem"
	publicKeyFileName         = "public.pem"
	orgPasswordBackupFileName = "orgpassword.bin"
	newPasswordBackupFileName = "newpassword.bin"
	tmpCycledFileSuffix       = ".cycled"
)

func cycleCommand() *cobra.Command {
	var cycleArgs args
	cycleCommand := &cobra.Command{
		Use:   "cycle",
		Short: "cycle encryption key and file",
		Long:  `Use this command to generate a new key/file from previous key/file.`,
		Run: func(cmd *cobra.Command, args []string) {

			setVerbosity(cycleArgs.GetInt("verbose"))
			encryptedFile := cycleArgs.GetString("encryptedFile")
			if encryptedFile == "" {
				log.Panic("parameter encryptedFile is mandatory for cycle")
			}

			//tmp dir for tmp asym keys and tmp backups
			tmpDir, err := os.MkdirTemp("", "cycle")
			if err != nil {
				log.Panicf("failed to create temp dir: %w", err)
			}

			//generate tmp backup and restore keys
			tmpPrivateKeyPath := filepath.Join(tmpDir, privateKeyFileName)
			tmpPrivateKey, err := asymmetric.GeneratePrivateKey(tmpPrivateKeyPath)
			if err != nil {
				log.Panicf("failed to generate tmp private key: %w", err)
			}

			tmpPublicKeyPath := filepath.Join(tmpDir, publicKeyFileName)
			tmpPublicKey, err := asymmetric.PrivateToPublic(tmpPrivateKey, tmpPublicKeyPath)
			if err != nil {
				log.Panicf("writing public key failed: %w", err)
			}
			log.Infof("using tmp backup key in %s for encrypting passwords", tmpPublicKeyPath)
			log.Infof("you can recover secrets with tmp recovery key in %s", tmpPrivateKeyPath)

			//retrieve password from vault
			client := cycleArgs.GetClient()
			secretKey := cycleArgs.GetString("secretKey")
			secretPath := cycleArgs.GetString("secretPath")
			passwordFromVault, err := client.GetSecret(secretPath, secretKey)
			if err != nil {
				log.Panicf("failed to get secret from vault: %w", err)
			}
			log.Infof("succesfully retrieved original password from vault")

			//write org password to tmp backup
			originalPasswordBackupFilePath := path.Join(tmpDir, orgPasswordBackupFileName)
			err = asymmetric.EncryptToFile(tmpPublicKey, originalPasswordBackupFilePath, encryptedFile, []byte(passwordFromVault))
			if err != nil {
				log.Panicf("failed to backup original password: %w", err)
			}
			log.Infof("you can recover original password from %s", originalPasswordBackupFilePath)

			//generate new password
			pwLength := cycleArgs.GetUint("generatedPasswordLength")
			pwChars := cycleArgs.GetString("generatedPasswordChars")
			newPassword := passwordGen.RandomPassword(pwLength, pwChars)
			log.Info("successfully generated new password")

			//write new password to tmp backup
			newPasswordBackupFilePath := path.Join(tmpDir, newPasswordBackupFileName)
			err = asymmetric.EncryptToFile(tmpPublicKey, newPasswordBackupFilePath, encryptedFile, []byte(newPassword))
			if err != nil {
				log.Panicf("failed to backup new password: %w", err)
			}
			log.Infof("you can recover newly generated password from %s", newPasswordBackupFilePath)

			//stream from org file with orgpw, write to newfile with newpw
			decryptionKey := symmetric.PasswordToKey(passwordFromVault, keySize.ToAESKeySize())
			encryptionKey := symmetric.PasswordToKey(newPassword, keySize.ToAESKeySize())
			cycledFile := encryptedFile + tmpCycledFileSuffix
			err = symmetric.Cycle(decryptionKey, encryptedFile, encryptionKey, cycledFile)
			if err != nil {
				log.Panicf("cycling old password and old file into new password and new file failed: %w", err)
			}
			log.Infof("successfully cycled %s to %s", encryptedFile, cycledFile)

			now := time.Now().Format(time.DateTime)
			now = strings.ReplaceAll(now, " ", "_")
			now = strings.ReplaceAll(now, ":", "-")
			encryptedFileBackup := encryptedFile + now
			err = os.Rename(encryptedFile, encryptedFileBackup)
			if err != nil {
				log.Panicf("renaming old encrypted file %s to %s failed: %w", encryptedFile, encryptedFileBackup, err)
			}
			log.Infof("successfully renamed %s to %s", encryptedFile, encryptedFileBackup)
			err = os.Rename(cycledFile, encryptedFile)
			if err != nil {
				log.Panicf("renaming old encrypted file %s to %s failed: %w", encryptedFile, encryptedFileBackup, err)
			}
			log.Infof("successfully renamed %s to %s", cycledFile, encryptedFile)

			//write new password to vault
			data := map[string]string{
				secretKey: newPassword,
			}
			if err = client.PatchSecret(secretPath, data); err != nil {
				log.Panicf("unable to patch new password: %w", err)
			}
			log.Infof("new password updated in vault.")

			//if public key is set, encrypt new password with public key and write to backup file
			publicKeyPath := cycleArgs.GetString("publicKeyPath")
			backupFilePath := cycleArgs.GetString("backupFile")
			if key, err := asymmetric.ReadPublicKeyFromFile(publicKeyPath); err != nil {
				log.Errorf("failed to read private key: %w", err)
				log.Info("password backup feature disabled")
			} else if err = asymmetric.EncryptToFile(key, backupFilePath, encryptedFile, []byte(newPassword)); err != nil {
				log.Panicf("failed to update backup file: %w", err)
			} else {
				log.Infof("password backup file (%s) successfully updated", backupFilePath)
			}

			// shred tmp keys, files, etc.
			if cycleArgs.GetBool("shred") {
				shredConf := shred.Conf{Times: 1, Zeros: true, Remove: false}
				if err = shredConf.Path(tmpDir); err != nil {
					log.Panicf("failed to shred tmp backup and restore files, please manually clean folder: %w", err)
				}
				log.Infof("tmp backup and restore folder %s is successfully shredded", tmpDir)
			} else {
				log.Info("shredding tmp backup and restore folder is disabled", tmpDir)
			}
		},
	}

	cycleArgs = allArgs.commandArgs(cycleCommand, append(globalArgs,
		"backupFile",
		"encryptedFile",
		"generatedPasswordChars",
		"generatedPasswordLength",
		"publicKeyPath",
		"secretKey",
		"secretPath",
		"shred",
	))
	return cycleCommand
}

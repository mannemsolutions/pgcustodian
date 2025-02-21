package main

import (
	"mannemsolutions/pgcustodian/pkg/asymmetric"
	"mannemsolutions/pgcustodian/pkg/utils"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/*
generate (pg_ctl start):
  env:
    file path
	key path
	vault token
  stdout: pg generateed something from generatee
*/

func generateCommand() *cobra.Command {
	generateCommand := &cobra.Command{
		Use:   "generate",
		Short: "generate asymmetric keys which can be used to backup the secret",
		Long: `Use this command to generate a key pair which can be used to backup and recover the encryption key.
It is best to run this command on a separate server, and only ship the public key to the server running pgcustodian.
Supply the public key to pgcustodian and safely store the public key safely in a store where only high ranking officers can get access to it when necessary.
Always make sure you shred the private key rather then removing it once safely moved to secure storage.
If the public key is supplied, the encryption key is encrypted and stored next to the encrypted data.
Should the primary storage (Vault) be lost the encryption key can be recovered with the private key.`,
		Run: func(cmd *cobra.Command, args []string) {
			setVerbosity(viper.GetInt("verbose"))
			privateKeyPath := utils.ResolveHome(viper.GetString("privateKey"))
			if privateKeyPath == "" {
				if privateKeyFile, err := os.CreateTemp("", "private*.pem"); err != nil {
					log.Panicf("failed to create tempfile for private key: %w", err)
				} else {
					privateKeyPath = privateKeyFile.Name()
				}
			}
			privateKey, err := asymmetric.GeneratePrivateKey(privateKeyPath)
			if err != nil {
				log.Panicf("failed to generate private key: %w", err)
			}
			log.Infof("succesfully generated and stored private key as %s", privateKeyPath)
			publicKeyPath := utils.ResolveHome(viper.GetString("publicKey"))
			if publicKeyPath == "" {
				if publicKeyFile, err := os.CreateTemp("", "public*.pem"); err != nil {
					log.Panicf("failed to create tempfile for public key: %w", err)
				} else {
					publicKeyPath = publicKeyFile.Name()
				}
			}
			if _, err = asymmetric.PrivateToPublic(privateKey, publicKeyPath); err != nil {
				log.Panicf("failed to store public key: %w", err)
			}
			log.Infof("succesfully stored public key as %s", publicKeyPath)
		},
	}

	return generateCommand
}

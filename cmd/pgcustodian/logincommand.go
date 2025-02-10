package main

// Implementation of the "add" sub command.

import (
	"mannemsolutions/pgcustodian/pkg/crypt"
	"mannemsolutions/pgcustodian/pkg/vault"

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

func loginCommand() *cobra.Command {
	loginCommand := &cobra.Command{
		Use:   "login",
		Short: "login and generate token",
		Long: `Use this command to login to Vault and generate a onetime token.
		This command can be run by a high privileged user, and the resulting token 
		can be delivered to the low privileged user for onetime authentication,
		thus resulting in separation between credentials and service utilizing the key.`,
		Run: func(cmd *cobra.Command, args []string) {
			setVerbosity(viper.GetInt("verbose"))
			client := vault.NewClient()
			client.IsWrapped = viper.GetBool("wrapped")
			client.RoleID = viper.GetString("roleid")
			client.SecretIDFile = viper.GetString("secretIdFile")
			if err := client.Connect(); err != nil {
				log.Panicf("failed to login: %w", err)
			}
			tokenFile := viper.GetString("tokenFile")
			if err := client.ExportTokenToFile(tokenFile); err != nil {
				log.Panicf("failed to export auth token: %w", err)
			}

		},
	}

	var keySize crypt.AESKeyEnum = crypt.AESKeyEnum256
	loginCommand.PersistentFlags().VarP(&keySize, "aesKeySize", "a", `key size for AES decryption.`)
	bindArgument("", "aesKeySize", loginCommand, []string{"PGC_AES_KEY_SIZE"}, 16)
	return loginCommand
}

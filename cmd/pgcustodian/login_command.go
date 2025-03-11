package main

import (
	"os"

	"github.com/spf13/cobra"
)

func loginCommand() *cobra.Command {
	var loginArgs args
	loginCommand := &cobra.Command{
		Use:   "login",
		Short: "login and generate token",
		Long: `Use this command to login to Vault and generate a onetime token.
This command can be run by a high privileged user, and the resulting token 
can be delivered to the low privileged user for onetime authentication,
thus resulting in separation between credentials and service utilizing the key.`,
		Run: func(cmd *cobra.Command, args []string) {
			setVerbosity(loginArgs.GetInt("verbose"))
			tokenFile := loginArgs.GetString("tokenFile")
			if stat, err := os.Stat(tokenFile); err != nil && os.IsNotExist(err) {
				log.Infof("tokenfile %s does not exist", tokenFile)
			} else if err != nil {
				log.Panicf("failed to get stat of tokenfile: %w", err)
			} else if stat.Mode().IsRegular() {
				err = os.RemoveAll(tokenFile)
				if err != nil {
					log.Panicf("failed to clean tokenfile: %w", err)
				}
			} else {
				log.Panic("tokenfile is an unexpected filetype")
			}
			client := loginArgs.GetClient()
			if err := client.Connect(); err != nil {
				log.Panicf("failed to login: %w", err)
			}
			if err := client.ExportTokenToFile(tokenFile); err != nil {
				log.Panicf("failed to export auth token: %w", err)
			}

		},
	}

	loginArgs = allArgs.commandArgs(loginCommand, append(globalArgs,
		"tokenFile",
	))
	return loginCommand
}

package main

// cobra and viper are used to create a uniform interface on CLI and configuration file.
import (
	"fmt"
	"mannemsolutions/pgcustodian/internal"
	"mannemsolutions/pgcustodian/pkg/crypt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	keySize crypt.AESKeyEnum = crypt.AESKeyEnum256
)

// requireSubcommand returns an error if no sub command is provided
// This was copied from skopeo, which copied it from podman: `github.com/containers/podman/cmd/podman/validate/args.go
// Some small style changes to match skopeo were applied, but try to apply any
// bugfixes there first.
func requireSubcommand(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		suggestions := cmd.SuggestionsFor(args[0])
		if len(suggestions) == 0 {
			return fmt.Errorf("unrecognized command `%[1]s %[2]s`\nTry '%[1]s --help' for more information", cmd.CommandPath(), args[0])
		}
		return fmt.Errorf("unrecognized command `%[1]s %[2]s`\n\nDid you mean this?\n\t%[3]s\n\nTry '%[1]s --help' for more information", cmd.CommandPath(), args[0], strings.Join(suggestions, "\n\t"))
	}
	return fmt.Errorf("missing command '%[1]s COMMAND'\nTry '%[1]s --help' for more information", cmd.CommandPath())
}

// createApp returns either a validly formed command for main() to run, or
// an error. Initializes a cobra command structure using the settings from the
// configuration file. Override the default location with -c,--cfgFile).
// Override the target pg_hba.conf file with -f, --hbaFile
func createApp() *cobra.Command {

	cobra.OnInitialize(initConfig)

	rootCmd := &cobra.Command{
		Use:   "pgcustodian",
		Short: "Vault integration for PostgreSQL TDE implementations",
		Long: `The pgcustodian tool allows for storing TDE encryption keys on filesystem in a safe manner.
		When writing the files, they are encrypted with a key which is stored in Hashicorp Vault.
		When retrieving they are decrypted with the same key, again retrieved from Hashicorp Vault.
		pgcustodian can run with an AppRole, with shortlived / onetime tokens, which means that 
		the vault credentials never reach Postgres, and that Postgres can only read TDE keys once (before starting).
		
		Complete documentation is available at https://github.com/mannemsolutions/pgcustodian/`,
		RunE:              requireSubcommand,
		CompletionOptions: cobra.CompletionOptions{},
		TraverseChildren:  true,
		Version:           internal.GetAppVersion(),
		//SilenceErrors: true,
		//SilenceUsage: true,
	}
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("current user couldn't be detected")
	}
	rootCmd.PersistentFlags().CountP("verbose", "v",
		`Be more verbose in the output.`)
	bindArgument("", "verbose", rootCmd, []string{"PGC_VERBOSE"}, "0")

	rootCmd.PersistentFlags().StringP("cfgFile", "c", "", "config file (default is $HOME/.pgcustodian.yaml)")
	bindArgument("", "cfgFile", rootCmd, []string{"PGC_CFG"}, filepath.Join(currentUser.HomeDir, ".pgcustodian.yaml"))
	viper.AddConfigPath(viper.GetString("cfgFile"))
	err = viper.ReadInConfig()
	if err == nil {
		fmt.Printf("pgcustodian is reading config from this config file: %s", viper.ConfigFileUsed())
	}

	rootCmd.PersistentFlags().StringP("tokenFile", "T", "~/.vault/token",
		`tokenFile can be set to a path containing the token for logging into vault.
		If token is set, tokenFile is unused.
		If either tokenFile or token are set, roleId and secretId are unused.
		Defaults are derived from PGC_TOKEN_FILE, and VAULT_TOKE_FILE in that order.`)
	bindArgument("", "tokenFile", rootCmd, []string{"PGC_TOKEN_FILE", "VAULT_TOKEN_FILE"}, "~/.vault/token")

	rootCmd.PersistentFlags().StringP("token", "t", "",
		`token for logging into vault.
		If token is set, roleId and secretId are unused.
		Defaults are derived from PGC_TOKEN, and VAULT_TOKEN in that order.`)
	bindArgument("", "token", rootCmd, []string{"PGC_TOKEN", "VAULT_TOKEN"}, "")

	rootCmd.PersistentFlags().StringP("roleId", "r", "",
		`role id for logging into vault.
		Defaults are derived from PGC_ROLE_ID.`)
	bindArgument("", "roleId", rootCmd, []string{"PGC_ROLE_ID"}, "")

	rootCmd.PersistentFlags().StringP("secretIdFile", "s", "",
		`secret id for logging into vault.
		Defaults are derived from PGC_SECRET_ID_FILE.`)
	bindArgument("", "secretIdFile", rootCmd, []string{"PGC_SECRET_ID_FILE"}, "")

	rootCmd.PersistentFlags().Uint8P("storeVersion", "V", 2,
		`version of vault store.`)
	bindArgument("", "storeVersion", rootCmd, []string{"PGC_STORE_VERSION"}, 2)

	rootCmd.PersistentFlags().StringP("storePath", "p", "",
		`path to kv1 or kv2 store where secrets are held.`)
	bindArgument("", "storePath", rootCmd, []string{"PGC_STORE_PATH"}, "secret")

	rootCmd.PersistentFlags().StringP("secretPath", "P", "",
		`path in kv1 or kv2 store where secrets are held.`)
	bindArgument("", "secretPath", rootCmd, []string{"PGC_SECRET_PATH"}, "")

	rootCmd.PersistentFlags().StringP("secretKey", "k", "",
		`path in kv1 or kv2 store where secrets are held.`)
	bindArgument("", "secretKey", rootCmd, []string{"PGC_SECRET_KEY"}, "")

	rootCmd.PersistentFlags().StringP("encryptedFile", "f", "",
		`path to file with decrypted version of data.`)
	bindArgument("", "encryptedFile", rootCmd, []string{"PGC_ENCRYPTED_FILE"}, "")

	rootCmd.PersistentFlags().VarP(&keySize, "aesKeySize", "a", `key size for AES encryption.`)
	bindArgument("", "aesKeySize", rootCmd, []string{"PGC_AES_KEY_SIZE"}, 16)

	rootCmd.AddCommand(
		encryptCommand(),
		decryptCommand(),
		cycleCommand(),
		loginCommand(),
		exportCommand(),
	)
	return rootCmd
}

// Execute the fully formed pgcustodian command and handle any errors.
func main() {
	initLogger("")
	rootCmd := createApp()
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	log.Info("finished")
}

// Read settings as key value pairs from the ".pgcustodian" config file in the home directory.
// This is (obscurely) referenced from the "createApp" function above.
// TODO would this be clearer if moved above createApp?
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".pgcustodian")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

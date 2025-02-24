package main

import (
	"fmt"
	"mannemsolutions/pgcustodian/pkg/utils"
	"mannemsolutions/pgcustodian/pkg/vault"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func setupClient() *vault.Client {
	client := vault.NewClient()
	client.IsWrapped = viper.GetBool("wrapped")
	client.RoleID = viper.GetString("roleId")
	client.SetRoleIdFromFile(utils.ResolveHome(viper.GetString("roleIdFile")))
	client.SecretID.FromFile = utils.ResolveHome(viper.GetString("secretIdFile"))
	storeVersion := uint8(viper.GetUint("storeVersion"))
	if storeVersion < 1 || storeVersion > 2 {
		storeVersion = vault.DefaultStoreVersion
	}
	if viper.GetString("storePath") != "" {
		client.StorePath = viper.GetString("storePath")
	} else {
		client.StorePath = vault.DefaultStore(storeVersion)
	}
	client.StoreVersion = storeVersion
	client.SetToken(viper.GetString("token"))
	client.SetTokenFromFile(utils.ResolveHome(viper.GetString("tokenFile")))
	return client
}

// bindArgument
func bindArgument(ns string, key string, cmd *cobra.Command, envVars []string, defaultValue any) {
	var err error
	var viperKey string
	if ns == "" {
		viperKey = key
	} else {
		viperKey = fmt.Sprintf("%s.%s", ns, key)
	}
	err = viper.BindPFlag(viperKey, cmd.PersistentFlags().Lookup(key))
	if err != nil {
		log.Fatalf("error while binding argument for %s: %e", key, err)
	}
	if len(envVars) > 0 {
		envVars = append([]string{key}, envVars...)
		err = viper.BindEnv(envVars...)
		if err != nil {
			log.Fatal("error while binding env var for %s: %e", viperKey, err)
		}
	}
	viper.SetDefault(viperKey, defaultValue)
}

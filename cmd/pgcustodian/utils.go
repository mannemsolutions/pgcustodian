package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// getArg returns the value for 'key' in namespace 'ns'
// A namespace is related to a sub command, allowing for options per sub-command
// func getArg(ns, key string) string {
// 	return viper.GetString(fmt.Sprintf("%s.%s", ns, key))
// }

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

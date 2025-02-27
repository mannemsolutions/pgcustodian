package main

import (
	"fmt"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/symmetric"
	"mannemsolutions/pgcustodian/pkg/utils"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type aType int

const (
	typeCount aType = iota
	typeUInt
	typeBool
	typeString
	typePath
	typeVaultPath
	typeVaultToken
	typeVaultId
	typeAes
	typeUnknown
)

var (
	typeToString = map[aType]string{
		typeCount:      "typeCount",
		typeUInt:       "typeUInt",
		typeBool:       "typeBool",
		typeString:     "typeString",
		typePath:       "typePath",
		typeVaultPath:  "typeVaultPath",
		typeVaultToken: "typeVaultToken",
		typeVaultId:    "typeVaultId",
		typeAes:        "typeAes",
		typeUnknown:    "typeUnknown",
	}
)

func (at aType) String() string {
	value, exists := typeToString[at]
	if !exists {
		return typeUnknown.String()
	}
	return value
}

const (
	confDir = "~/.pgcustodian"
)

type arg struct {
	short        string
	desc         string
	extraEnvVars []string
	defValue     any
	argType      aType
	stringValue  *string
	aesValue     *symmetric.AESKeyEnum
	uIntValue    *uint
	intValue     *int
	boolValue    *bool
}

type args map[string]arg

var (
	matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
	matchAllCap   = regexp.MustCompile("([a-z0-9])([A-Z])")
	keySize       = symmetric.AESKeyEnum256

	globalArgs = args{
		"aesKeySize":              {short: "a", defValue: 16, argType: typeAes, desc: `key size for AES encryption.`},
		"backupFile":              {short: "b", argType: typePath, desc: `path to backup file with secret encrypted with public key.`},
		"cfgFile":                 {short: "c", defValue: confDir, argType: typeString, desc: `config file`},
		"customPolicyFile":        {short: "C", defValue: customPolicyFile, argType: typePath, desc: `file with custom policy to be applied`},
		"encryptedFile":           {short: "f", argType: typePath, desc: `path to file with decrypted version of data.`},
		"generatedPasswordLength": {short: "g", defValue: 16, argType: typeUInt, desc: `length for generated passwords`},
		"generatedPasswordChars":  {short: "G", defValue: passwordGen.AllBytes, argType: typeString, desc: `character list for generating passwords`},
		"publicKeyPath":           {short: "k", defValue: confDir + "/public.pem", argType: typePath, desc: `path where public key should be stored.`},
		"privateKeyPath":          {short: "K", defValue: confDir + "/private.pem", argType: typePath, desc: `path where private key should be stored.`},
		"roleName":                {short: "n", defValue: getHostName(), argType: typeVaultId, desc: `role id for logging into vault.`},
		"storePath":               {short: "p", argType: typeVaultPath, desc: `path where private key should be stored.`},
		"secretPath":              {short: "P", defValue: "pgcustodian/" + getHostName(), argType: typeVaultPath, desc: `path in kv1 or kv2 store where secrets are held.`},
		"secretKey":               {short: "S", argType: typeVaultPath, desc: `path in kv1 or kv2 store where secrets are held.`},
		"secretIdFile":            {short: "s", defValue: confDir + "/secret-id", argType: typePath, desc: `secret id for logging into vault.`},
		"token":                   {short: "t", extraEnvVars: []string{"VAULT_TOKEN"}, argType: typePath, desc: `token for logging into vault.`},
		"tokenFile":               {short: "T", defValue: confDir + "/token", argType: typePath, desc: `tokenFile can be set to a path containing the token for logging into vault.`},
		"roleId":                  {short: "r", extraEnvVars: []string{"VAULT_TOKEN"}, argType: typeVaultId, desc: `role id for logging into vault.`},
		"roleIdFile":              {short: "R", defValue: confDir + "/role-id", argType: typePath, desc: `path to file with role id for logging into vault.`},
		"verbose":                 {short: "v", defValue: 0, argType: typeCount, desc: `Be more verbose in the output.`},
		"storeVersion":            {short: "V", defValue: 2, argType: typeUInt, desc: `version of vault store.`},
		"shred":                   {short: "x", defValue: true, argType: typeBool, desc: `shred the tmp files`},
	}
)

func (as args) commandArgs(command *cobra.Command, enabledArguments []string) (cmdArgs args) {
	cmdArgs = make(args)
	for _, key := range enabledArguments {
		argConfig, exists := as[key]
		if !exists {
			panic(fmt.Sprintf("requested argument %s does not seem to exist", key))
		}
		envVars := append(argConfig.extraEnvVars, "PGC_"+strings.ToUpper(toSnakeCase(key)))
		switch argConfig.argType {
		case typeCount:
			argConfig.intValue = command.PersistentFlags().CountP(key, argConfig.short, argConfig.desc)
			bindArgument(key, command, envVars, argConfig.defValue)
		case typeUInt:
			defaultValue, ok := argConfig.defValue.(uint)
			if !ok {
				panic(
					fmt.Sprintf(
						"requested argument %s is %s, but %v cannot be parsed to %T",
						key,
						argConfig.argType.String(),
						argConfig.defValue,
						defaultValue,
					))
			}
			argConfig.uIntValue = command.PersistentFlags().UintP(key, argConfig.short, defaultValue, argConfig.desc)
			bindArgument(key, command, envVars, argConfig.defValue)
		case typePath, typeString, typeVaultId, typeVaultPath, typeVaultToken:
			defaultValue, ok := argConfig.defValue.(string)
			if argConfig.argType == typePath {
				defaultValue = path.Join(confDir, defaultValue)
			}
			if !ok {
				panic(
					fmt.Sprintf(
						"requested argument %s is %s, but %v cannot be parsed to %T",
						key,
						argConfig.argType.String(),
						argConfig.defValue,
						defaultValue,
					))
			}
			argConfig.stringValue = command.PersistentFlags().StringP(key, argConfig.short, defaultValue, argConfig.desc)
			bindArgument(key, command, envVars, defaultValue)
		case typeAes:
			defaultValue, ok := argConfig.defValue.(symmetric.AESKeyEnum)
			if !ok {
				panic(
					fmt.Sprintf(
						"requested argument %s is %s, but %v cannot be parsed to %T",
						key,
						argConfig.argType.String(),
						argConfig.defValue,
						defaultValue,
					))
			}
			command.PersistentFlags().VarP(argConfig.aesValue, "aesKeySize", "a", `key size for AES encryption.`)
			bindArgument(key, command, envVars, defaultValue)
		case typeBool:
			defaultValue, ok := argConfig.defValue.(bool)
			if !ok {
				panic(
					fmt.Sprintf(
						"requested argument %s is %s, but %v cannot be parsed to %T",
						key,
						argConfig.argType.String(),
						argConfig.defValue,
						defaultValue,
					))
			}
			command.PersistentFlags().VarP(argConfig.aesValue, "aesKeySize", "a", `key size for AES encryption.`)
			bindArgument(key, command, envVars, defaultValue)

		}
	}
	return cmdArgs
}
func (as args) GetString(argument string) (value string) {
	arg, exists := as[argument]
	if !exists {
		panic(fmt.Sprintf("requesting %s, but it is not defined", argument))
	}
	switch arg.argType {
	case typePath:
		value = utils.ResolveHome(confDir + *arg.stringValue)
		return value
	case typeString, typeVaultId, typeVaultPath, typeVaultToken:
		value = *arg.stringValue
		return value
	default:
		panic(fmt.Sprintf("requesting string value for %s, but it is not defined as such", argument))
	}

}

// bindArgument
func bindArgument(key string, cmd *cobra.Command, envVars []string, defaultValue any) {
	var err error
	err = viper.BindPFlag(key, cmd.PersistentFlags().Lookup(key))
	if err != nil {
		log.Fatalf("error while binding argument for %s: %e", key, err)
	}
	if len(envVars) > 0 {
		envVars = append([]string{key}, envVars...)
		err = viper.BindEnv(envVars...)
		if err != nil {
			log.Fatal("error while binding env var for %s: %e", key, err)
		}
	}
	viper.SetDefault(key, defaultValue)
}
func getHostName() string {
	hostName, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	return hostName

}

func toSnakeCase(str string) string {
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")
	return strings.ToLower(snake)
}

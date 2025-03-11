package main

import (
	"fmt"
	passwordGen "mannemsolutions/pgcustodian/pkg/pwgen"
	"mannemsolutions/pgcustodian/pkg/symmetric"
	"mannemsolutions/pgcustodian/pkg/utils"
	"mannemsolutions/pgcustodian/pkg/vault"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
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
	confDir          = "~/.pgcustodian"
	customPolicyFile = confDir + "/custom_policy.hcl"
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

func FromEnv(keys []string) string {
	for _, key := range keys {
		fromEnv := os.Getenv(key)
		if fromEnv != "" {
			return fromEnv
		}
	}
	return ""

}

type args map[string]arg

var (
	matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
	matchAllCap   = regexp.MustCompile("([a-z0-9])([A-Z])")
	keySize       = symmetric.AESKeyEnum256

	allArgs = args{
		"aesKeySize":              {short: "a", defValue: 16, argType: typeAes, desc: `key size for AES encryption.`},
		"backupFile":              {short: "b", argType: typePath, desc: `path to backup file with secret encrypted with public key.`},
		"cfgFile":                 {short: "c", defValue: "config.yaml", argType: typePath, desc: `config file`},
		"customPolicyFile":        {short: "C", defValue: customPolicyFile, argType: typePath, desc: `file with custom policy to be applied`},
		"encryptedFile":           {short: "f", argType: typePath, desc: `path to file with decrypted version of data.`},
		"generatedPasswordLength": {short: "g", defValue: 16, argType: typeUInt, desc: `length for generated passwords`},
		"generatedPasswordChars":  {short: "G", defValue: passwordGen.AllBytes, argType: typeString, desc: `character list for generating passwords`},
		"publicKeyPath":           {short: "k", defValue: "/public.pem", argType: typePath, desc: `path where public key should be stored.`},
		"privateKeyPath":          {short: "K", defValue: "/private.pem", argType: typePath, desc: `path where private key should be stored.`},
		"roleName":                {short: "n", defValue: getHostName(), argType: typeVaultId, desc: `role id for logging into vault.`},
		"storePath":               {short: "p", argType: typeVaultPath, desc: `path where private key should be stored.`},
		"secretPath":              {short: "P", defValue: "pgcustodian/" + getHostName(), argType: typeVaultPath, desc: `path in kv1 or kv2 store where secrets are held.`},
		"secretKey":               {short: "S", argType: typeVaultPath, desc: `path in kv1 or kv2 store where secrets are held.`},
		"secretIdFile":            {short: "s", defValue: "/secret-id", argType: typePath, desc: `secret id for logging into vault.`},
		"token":                   {short: "t", extraEnvVars: []string{"VAULT_TOKEN"}, argType: typeString, desc: `token for logging into vault.`},
		"tokenFile":               {short: "T", defValue: "/token", argType: typePath, desc: `tokenFile can be set to a path containing the token for logging into vault.`},
		"roleId":                  {short: "r", argType: typeVaultId, desc: `role id for logging into vault.`},
		"roleIdFile":              {short: "R", defValue: "/role-id", argType: typePath, desc: `path to file with role id for logging into vault.`},
		"verbose":                 {short: "v", defValue: 0, argType: typeCount, desc: `Be more verbose in the output.`},
		"storeVersion":            {short: "V", defValue: 2, argType: typeUInt, desc: `version of vault store.`},
		"wrapped":                 {short: "w", defValue: false, argType: typeBool, desc: `wrap replies with the token`},
		"shred":                   {short: "x", defValue: true, argType: typeBool, desc: `shred the tmp files`},
	}
)

func (as args) commandArgs(command *cobra.Command, enabledArguments []string) (myArgs args) {
	myArgs = make(args)
	for _, key := range enabledArguments {
		if _, exists := myArgs[key]; exists {
			continue
		}
		argConfig, exists := as[key]
		if !exists {
			panic(fmt.Sprintf("requested argument %s does not seem to exist", key))
		}
		envVars := append(argConfig.extraEnvVars, "PGC_"+strings.ToUpper(toSnakeCase(key)))
		defaultFromEnv := FromEnv(envVars)
		switch argConfig.argType {
		case typeCount:
			// if defaultFromEnv != "" {
			// 	var err error
			// 	argConfig.defValue, err = strconv.Atoi(defaultFromEnv)
			// 	if err != nil {
			// 		panic(fmt.Sprintf("default %s from environment vars %v is not a valid int", defaultFromEnv, envVars))
			// 	}
			// } else if argConfig.defValue == nil {
			// 	argConfig.defValue = 0
			// }
			argConfig.intValue = command.PersistentFlags().CountP(key, argConfig.short, argConfig.desc)
		case typeUInt:
			if defaultFromEnv != "" {
				var err error
				argConfig.defValue, err = strconv.Atoi(defaultFromEnv)
				if err != nil {
					panic(fmt.Sprintf("default from environment (%v) is invalid as int", envVars))
				}
			} else if argConfig.defValue == nil {
				argConfig.defValue = 0
			}
			defaultValue, ok := argConfig.defValue.(int)
			if !ok {
				panic(
					fmt.Sprintf(
						"requested argument %s is %s, but %v (%T) cannot be parsed to %T",
						key,
						argConfig.argType.String(),
						argConfig.defValue,
						argConfig.defValue,
						defaultValue,
					))
			}
			argConfig.uIntValue = command.PersistentFlags().UintP(key, argConfig.short, uint(defaultValue), argConfig.desc)
		case typePath, typeString, typeVaultId, typeVaultPath, typeVaultToken:
			if defaultFromEnv != "" {
				argConfig.defValue = defaultFromEnv
			} else if argConfig.defValue == nil {
				argConfig.defValue = ""
			}
			defaultValue, ok := argConfig.defValue.(string)
			if !ok {
				panic(
					fmt.Sprintf(
						"requested argument %s is %s, but %v (%T) cannot be parsed to %T",
						key,
						argConfig.argType.String(),
						argConfig.defValue,
						argConfig.defValue,
						defaultValue,
					))
			}
			if argConfig.argType == typePath {
				defaultValue = path.Join(confDir, defaultValue)
			}
			argConfig.stringValue = command.PersistentFlags().StringP(key, argConfig.short, defaultValue, argConfig.desc)
		case typeAes:
			if defaultFromEnv != "" {
				aesKeyEnum := symmetric.AESKeyEnum(defaultFromEnv)
				// Try to convert Key Enum to valid Key Size, panics when it fails
				_ = aesKeyEnum.ToAESKeySize()
				argConfig.defValue = aesKeyEnum
			} else if argConfig.defValue == nil {
				argConfig.defValue = symmetric.AESKeyEnum256
			}
			defaultValue, ok := argConfig.defValue.(symmetric.AESKeyEnum)
			if !ok {
				panic(
					fmt.Sprintf(
						"requested argument %s is %s, but %v (%T) cannot be parsed to %T",
						key,
						argConfig.argType.String(),
						argConfig.defValue,
						argConfig.defValue,
						defaultValue,
					))
			}
			command.PersistentFlags().VarP(argConfig.aesValue, key, argConfig.short, argConfig.desc)
		case typeBool:
			if defaultFromEnv != "" {
				var err error
				argConfig.defValue, err = strconv.ParseBool(defaultFromEnv)
				if err != nil {
					panic(fmt.Sprintf("default %s from environment vars %v is not a valid bool", defaultFromEnv, envVars))
				}
			} else if argConfig.defValue == nil {
				argConfig.defValue = false
			}
			if argConfig.aesValue == nil {
				var aesValue symmetric.AESKeyEnum
				argConfig.aesValue = &aesValue
			}
			defaultValue, ok := argConfig.defValue.(bool)
			if !ok {
				panic(
					fmt.Sprintf(
						"requested argument %s is %s, but %v (%T) cannot be parsed to %T",
						key,
						argConfig.argType.String(),
						argConfig.defValue,
						argConfig.defValue,
						defaultValue,
					))
			}
			argConfig.boolValue = command.PersistentFlags().BoolP(key, argConfig.short, defaultValue, argConfig.desc)
		}
		myArgs[key] = argConfig
	}
	return myArgs
}

func (as args) GetString(argument string) (value string) {
	arg, exists := as[argument]
	if !exists {
		panic(fmt.Sprintf("requesting %s, but it is not defined", argument))
	}
	switch arg.argType {
	case typePath:
		value = utils.ResolveHome(*arg.stringValue)
		return value
	case typeString, typeVaultId, typeVaultPath, typeVaultToken:
		value = *arg.stringValue
		return value
	default:
		panic(fmt.Sprintf("requesting string value for %s, but it is not defined as such", argument))
	}
}

func (as args) GetInt(argument string) (value int) {
	arg, exists := as[argument]
	if !exists {
		panic(fmt.Sprintf("requesting %s, but it is not defined", argument))
	}
	if arg.argType != typeCount {
		panic(fmt.Sprintf("requesting int value for %s, but it is not defined as such", argument))
	}
	value = *arg.intValue
	return value
}

func (as args) GetUint(argument string) (value uint) {
	arg, exists := as[argument]
	if !exists {
		panic(fmt.Sprintf("requesting %s, but it is not defined", argument))
	}
	if arg.argType != typeUInt {
		panic(fmt.Sprintf("requesting uint value for %s, but it is not defined as such", argument))
	}
	value = *arg.uIntValue
	return value
}

func (as args) GetAES(argument string) (value symmetric.AESKeyEnum) {
	arg, exists := as[argument]
	if !exists {
		panic(fmt.Sprintf("requesting %s, but it is not defined", argument))
	}
	if arg.argType != typeAes {
		panic(fmt.Sprintf("requesting aes value for %s, but it is not defined as such", argument))
	}
	value = *arg.aesValue
	return value
}

func (as args) GetBool(argument string) (value bool) {
	arg, exists := as[argument]
	if !exists {
		panic(fmt.Sprintf("requesting %s, but it is not defined", argument))
	}
	if arg.argType != typeBool {
		panic(fmt.Sprintf("requesting bool value for %s, but it is not defined as such", argument))
	}
	value = *arg.boolValue
	return value
}

func (as args) GetClient() *vault.Client {
	client := vault.NewClient()
	client.IsWrapped = as.GetBool("wrapped")
	client.RoleID = as.GetString("roleId")
	client.SetRoleIdFromFile(utils.ResolveHome(as.GetString("roleIdFile")))
	client.SecretID.FromFile = utils.ResolveHome(as.GetString("secretIdFile"))
	storeVersion := uint8(as.GetUint("storeVersion"))
	if storeVersion < 1 || storeVersion > 2 {
		storeVersion = vault.DefaultStoreVersion
	}
	if as.GetString("storePath") != "" {
		client.StorePath = as.GetString("storePath")
	} else {
		client.StorePath = vault.DefaultStore(storeVersion)
	}
	client.StoreVersion = storeVersion
	client.SetToken(as.GetString("token"))
	client.SetTokenFromFile(utils.ResolveHome(as.GetString("tokenFile")))
	return client
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

package vault

import (
	"context"
	"fmt"
	"mannemsolutions/pgcustodian/pkg/utils"
	"os"
	"path/filepath"
	"strconv"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

const (
	// environment variable to set the App Role
	envRoleID = "PGC_ROLE_ID"
	// environment variable to set the path to the Secret ID file
	envSecretIDFile = "PGC_SECRET_ID_FILE"
	// environment variable to set the version of the kv store KVv1 or KVv2
	// Should be an integer in a string
	envStoreVersion = "PGC_STORE_VERSION"
	// Default version of the kv store KVv1 or KVv2
	defaultStoreVersion uint8 = 2
	// Default path of the kv store
	defaultStore = "secret"
)

type Client struct {
	// internal pointer to the client used to connect, get, set and update in vault
	client *vault.Client
	// internal token, can be set with SetToken() and SetTokenFromFile() methods
	token string
	// roleid to be used. Gathered from envSecretIDFile by NewCrypt()
	RoleID string
	// file to read secret ID from. Gathered from envRoleID by NewCrypt()
	SecretIDFile string
	// should the Secret ID be response wrapped
	IsWrapped bool
	// environment variable to set the version of the kv store KVv1 or KVv2
	// Should be an integer in a string
	StoreVersion uint8
	// path to the kv store
	StorePath string
}

// storeVersion is a convenience fucntion to get the store version from env vars
func storeVersion() (v uint8) {
	v = defaultStoreVersion
	if sVersion := os.Getenv(envStoreVersion); sVersion == "" {
		return
	} else if iVersion, err := strconv.Atoi(sVersion); err != nil {
		return
	} else if iVersion < 1 || iVersion > 2 {
		return
	} else {
		return uint8(iVersion)
	}
}

// NewClient will setup a new client with defaults from env vars
// values can be overwritten directly after instantiation
func NewClient() *Client {
	return &Client{
		nil,
		"",
		os.Getenv(envRoleID),
		os.Getenv(envSecretIDFile),
		false,
		storeVersion(),
		defaultStore,
	}
}

// SetToken is a convenience function to set the token (if not set already)
func (c *Client) SetToken(token string) {
	if c.token != "" {
		return
	}
	c.token = token
}

// SetTokenFromFile is a convenience function to set the token form file (if not set already)
func (c *Client) SetTokenFromFile(tokenFile string) {
	if c.token != "" {
		return
	}
	if dat, err := os.ReadFile(tokenFile); err != nil {
		return
	} else {
		c.token = string(dat)
	}
}

// ExportTokenToFile is a convenience function to export the token to a file
func (c *Client) ExportTokenToFile(tokenFile string) (err error) {
	if c.token == "" {
		return fmt.Errorf("token is not set")
	}
	tokenFile = utils.ResolveHome(tokenFile)
	if err = utils.MakeTree(filepath.Dir(tokenFile)); err != nil {
		return fmt.Errorf("failed to create folders: %w", err)
	}
	if err = os.WriteFile(tokenFile, []byte(c.token), 0600); err != nil {
		return fmt.Errorf("failed to write token: %w", err)
	}
	return nil
}

// Connect will authenticating via token or AppRole
func (c *Client) Connect() error {
	if c.client != nil {
		return nil
	}
	config := vault.DefaultConfig() // modify for more granular configuration
	client, err := vault.NewClient(config)
	if err != nil {
		return fmt.Errorf("unable to initialize Vault client: %w", err)
	}
	if c.token != "" {
		client.SetToken(c.token)
		c.client = client
		return nil
	}

	secretIDFile := &auth.SecretID{FromFile: c.SecretIDFile}

	var authOpts []auth.LoginOption
	if c.IsWrapped {
		authOpts = append(authOpts, auth.WithWrappingToken())
	}
	appRoleAuth, err := auth.NewAppRoleAuth(
		c.RoleID,
		secretIDFile,
		authOpts...,
	)
	if err != nil {
		return fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return fmt.Errorf("no auth info was returned after login")
	}
	c.client = client
	c.token = client.Token()
	return nil
}

// PatchSecret will patch a secret in the kv store by appending and/or updating values
func (c *Client) PatchSecret(secretPath string, secretKeyValues map[string]string) (err error) {
	if err = c.Connect(); err != nil {
		return fmt.Errorf("unable to connect: %w", err)
	}
	var data map[string]interface{}
	var secret *vault.KVSecret
	if c.StoreVersion == 2 {
		secret, err = c.client.KVv2(c.StorePath).Get(context.Background(), secretPath)
	} else {
		secret, err = c.client.KVv1(c.StorePath).Get(context.Background(), secretPath)
	}
	if err != nil {
		data = make(map[string]interface{})
	} else {
		data = secret.Data
	}

	for k, v := range secretKeyValues {
		data[k] = v
	}
	if c.StoreVersion == 2 {
		_, err = c.client.KVv2(c.StorePath).Put(context.Background(), secretPath, data)
	} else {
		err = c.client.KVv1(c.StorePath).Put(context.Background(), secretPath, data)
	}
	if err != nil {
		return fmt.Errorf("unable to write secret: %w", err)
	}

	return nil
}

// SetSecret will write a secret to the kv store
func (c *Client) SetSecret(secretPath string, secretKeyValues map[string]string) (err error) {
	if err = c.Connect(); err != nil {
		return fmt.Errorf("unable to connect: %w", err)
	}

	data := make(map[string]interface{})
	for k, v := range secretKeyValues {
		data[k] = v

	}
	if c.StoreVersion == 2 {
		_, err = c.client.KVv2(c.StorePath).Put(context.Background(), secretPath, data)
	} else {
		err = c.client.KVv1(c.StorePath).Put(context.Background(), secretPath, data)
	}
	if err != nil {
		return fmt.Errorf("unable to write secret: %w", err)
	}

	return nil
}

// GetSecret will get a secret from the kv store
func (c *Client) GetSecret(secretPath string, secretKey string) (value string, err error) {
	if err = c.Connect(); err != nil {
		return "", fmt.Errorf("unable to connect: %w", err)
	}

	var secret *vault.KVSecret
	if c.StoreVersion == 2 {
		secret, err = c.client.KVv2(c.StorePath).Get(context.Background(), secretPath)
	} else {
		secret, err = c.client.KVv1(c.StorePath).Get(context.Background(), secretPath)
	}
	if err != nil {
		return "", fmt.Errorf("unable to read secret: %w", err)
	}

	value, ok := secret.Data[secretKey].(string)
	if !ok {
		return "", fmt.Errorf("value type assertion failed: %T %#v", secret.Data[secretKey], secret.Data[secretKey])
	}

	return value, nil
}

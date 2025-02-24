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
	DefaultStoreVersion uint8 = 2
)

// Default path of the kv store
func DefaultStore(version uint8) string {
	if version == 1 {
		return "kv"
	} else if version == 2 {
		return "secret"
	}
	return DefaultStore(DefaultStoreVersion)
}

type Client struct {
	// internal pointer to the client used to connect, get, set and update in vault
	client *vault.Client
	// internal token, can be set with SetToken() and SetTokenFromFile() methods
	token string
	// roleid to be used. Gathered from envSecretIDFile by NewCrypt()
	RoleID string
	// file to read secret ID from. Gathered from envRoleID by NewCrypt()
	SecretID auth.SecretID
	// should the Secret ID be response wrapped
	IsWrapped bool
	// environment variable to set the version of the kv store KVv1 or KVv2
	// Should be an integer in a string
	StoreVersion uint8
	// path to the kv store
	StorePath string
}

// storeVersion is a convenience function to get the store version from env vars
func storeVersion() (v uint8) {
	v = DefaultStoreVersion
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
		auth.SecretID{
			FromFile: os.Getenv(envSecretIDFile),
		},
		false,
		storeVersion(),
		DefaultStore(storeVersion()),
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
func (c *Client) SetRoleIdFromFile(roleIdFile string) {
	if c.RoleID != "" {
		return
	}
	if dat, err := os.ReadFile(roleIdFile); err != nil {
		return
	} else {
		c.RoleID = string(dat)
	}
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

	var authOpts []auth.LoginOption
	if c.IsWrapped {
		authOpts = append(authOpts, auth.WithWrappingToken())
	}
	appRoleAuth, err := auth.NewAppRoleAuth(
		c.RoleID,
		&c.SecretID,
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

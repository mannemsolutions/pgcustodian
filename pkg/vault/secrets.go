package vault

import (
	"context"
	"fmt"

	vault "github.com/hashicorp/vault/api"
)

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

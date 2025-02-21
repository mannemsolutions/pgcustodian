package vault

import (
	vault "github.com/hashicorp/vault/api"
)

func (c *Client) EnableSecretStore(mountPath string, options *vault.MountInput) error {
	mounts, err := c.GetStores()
	if err != nil {
		return err
	}
	if _, exists := mounts[mountPath]; exists {
		return nil
	}
	return c.client.Sys().Mount(mountPath, options)
}

func (c *Client) DisableSecretStore(mountPath string) error {
	mounts, err := c.GetStores()
	if err != nil {
		return err
	}
	if _, exists := mounts[mountPath]; !exists {
		return nil
	}
	return c.client.Sys().Unmount(mountPath)
}

func (c *Client) GetStores() (stores map[string]bool, err error) {
	err = c.Connect()
	if err != nil {
		return nil, err
	}
	mountList, err := c.client.Sys().ListMounts()
	if err != nil {
		return nil, err
	}
	stores = make(map[string]bool)
	for path := range mountList {
		stores[path] = true
	}
	return stores, nil
}

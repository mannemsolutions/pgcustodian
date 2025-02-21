package vault

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/vault/api"
)

const (
	appRoleAuthKey     = "approle"
	appRoleLogicalPath = "auth/approle/role"
)

func (c *Client) EnableAppRoles() (err error) {
	enabled, err := c.AppRolesEnabled()
	if err != nil {
		return err
	}
	if enabled {
		return nil
	}
	return c.client.Sys().EnableAuthWithOptions(appRoleAuthKey, &api.EnableAuthOptions{Type: appRoleAuthKey})
}

func (c *Client) getAuthList() (authList map[string]bool, err error) {
	err = c.Connect()
	if err != nil {
		return nil, err
	}
	authMap, err := c.client.Sys().ListAuth()
	if err != nil {
		return nil, err
	}
	authList = make(map[string]bool)
	for key := range authMap {
		key, _ := strings.CutSuffix(key, "/")
		authList[key] = true
	}
	return authList, nil
}
func (c *Client) AppRolesEnabled() (enabled bool, err error) {
	authList, err := c.getAuthList()
	if err != nil {
		return false, err
	}
	_, enabled = authList[appRoleAuthKey]
	return enabled, nil
}

func (c *Client) DisableAppRoles() error {
	enabled, err := c.AppRolesEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	return c.client.Sys().DisableAuth(appRoleAuthKey)
}

func (c *Client) GetAppRoles() (data []string, err error) {
	enabled, err := c.AppRolesEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, errors.New("AppRoles are not enabled")
	}
	list, err := c.client.Logical().List(appRoleLogicalPath)
	if err != nil {
		return nil, err
	}
	if list.Data == nil {
		return nil, errors.New("list contains no data")
	}
	value, exists := list.Data["keys"]
	if !exists {
		return nil, errors.New("unexpected data in returned list")
	}
	switch reflect.TypeOf(value).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(value)
		for i := 0; i < s.Len(); i++ {
			data = append(data, s.Index(i).Elem().String())
		}
		return data, nil
	default:
		return nil, errors.New("unexpected result")
	}
}

func (c *Client) AddAppRole(name string, opts map[string]interface{}) (err error) {
	err = c.EnableAppRoles()
	if err != nil {
		return err
	}

	_, err = c.client.Logical().Write(
		fmt.Sprintf("%s/%s", appRoleLogicalPath, name),
		opts,
	)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) GetAppRoleId(name string) (appRoleId string, err error) {
	err = c.Connect()
	if err != nil {
		return "", err
	}
	reply, err := c.client.Logical().Read(
		fmt.Sprintf("%s/%s/role-id", appRoleLogicalPath, name),
	)
	if err != nil {
		return "", err
	}
	appRoleIdValue, exists := reply.Data["role_id"]
	if !exists {
		return "", fmt.Errorf("no role_id field in value %v", reply.Data)
	}

	return fmt.Sprintf("%v", appRoleIdValue), nil
}

func (c *Client) GetSecretId(appRoleName string) (secretId string, err error) {
	err = c.Connect()
	if err != nil {
		return "", err
	}
	reply, err := c.client.Logical().Write(
		fmt.Sprintf("%s/%s/secret-id", appRoleLogicalPath, appRoleName),
		map[string]interface{}{},
	)
	if err != nil {
		return "", err
	}
	secretIdValue, exists := reply.Data["secret_id"]
	if !exists {
		return "", fmt.Errorf("no role_id field in value %v", reply.Data)
	}

	return fmt.Sprintf("%v", secretIdValue), nil
}
func (c *Client) DeleteAppRole(name string) (err error) {
	err = c.EnableAppRoles()
	if err != nil {
		return err
	}
	_, err = c.client.Logical().Delete(
		fmt.Sprintf("%s/%s", appRoleLogicalPath, name),
	)
	return err
}

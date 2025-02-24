package vault

import "fmt"

func (c *Client) GetPolicies() (map[string]bool, error) {
	err := c.Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	policies := make(map[string]bool)
	policyList, err := c.client.Sys().ListPolicies()
	if err != nil {
		return nil, err
	}
	for _, policy := range policyList {
		policies[policy] = true
	}
	return policies, nil
}

func (c *Client) CreatePolicy(name string, rules string) error {
	err := c.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	return c.client.Sys().PutPolicy(name, rules)
}

func (c *Client) DeletePolicy(name string) error {
	err := c.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	return c.client.Sys().DeletePolicy(name)
}

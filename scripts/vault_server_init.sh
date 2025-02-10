#!/bin/sh
set -x
vault auth enable approle
vault write auth/approle/role/pgcustodian \
	token_type=service \
	token_max_ttl=30s \
	token_num_uses=6

vault policy write user_specific_path_policy /host/scripts/user_specific_path_policy.hcl
vault write auth/approle/role/pgcustodian policies=user_specific_path_policy
vault secrets enable -version=1 kv

mkdir -p /host/vaultcreds
echo "${VAULT_TOKEN}" >/host/vaultcreds/roottoken
vault read auth/approle/role/pgcustodian/role-id | awk '/role_id/{print $2}' >/host/vaultcreds/approleid
vault write -f auth/approle/role/pgcustodian/secret-id | awk '$1~/^secret_id$/{print $2}' >/host/vaultcreds/approlesecretid
grep -r '.' /host/vaultcreds

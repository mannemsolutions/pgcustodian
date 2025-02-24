#!/bin/sh
set -x
vault auth enable approle
vault write auth/approle/role/pgcustodian \
	token_type=service \
	token_max_ttl=30s \
	token_num_uses=10

vault policy write user_specific_path_policy /host/scripts/user_specific_path_policy.hcl
vault write auth/approle/role/pgcustodian policies=user_specific_path_policy
vault secrets enable -version=1 kv

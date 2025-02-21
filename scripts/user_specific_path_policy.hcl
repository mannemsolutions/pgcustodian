path "kv/pgcustodian/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "secret/data/pgcustodian/*" {
  capabilities = ["create", "update", "patch", "read", "delete"]
}


path "secret/metadata/pgcustodian/*" {
  capabilities = ["list"]
}

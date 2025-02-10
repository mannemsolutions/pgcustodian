#!/bin/bash
set -x

cd "$(dirname "$0")/.." || exit 1

COMPOSE=${COMPOSE:-"docker-compose"}
"${COMPOSE}" down
"${COMPOSE}" up vault -d
"${COMPOSE}" up vaultstage

PGC_SECRET_ID_FILE="$PWD/vaultcreds/approlesecretid"
PGC_ROLE_ID="$(cat vaultcreds/approleid)"
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=pgcustodian
export PGC_SECRET_ID_FILE PGC_ROLE_ID VAULT_ADDR VAULT_TOKEN

make check-coverage

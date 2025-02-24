#!/bin/sh
set -ex

VAULT_TOKEN=${PGC_TEST_ROOT_TOKEN} ./bin/pgcustodian stage -vv
SECRET=1234HvHv

./bin/pgcustodian login -vv
rm ~/.pgcustodian/role-id ~/.pgcustodian/secret-id

./bin/pgcustodian generate -vv

echo "${SECRET}" | ./bin/pgcustodian encrypt --encryptedFile=~/.pgcustodian/encrypted -b ~/.pgcustodian/backup -vv
DECRYPTED=$(./bin/pgcustodian decrypt --encryptedFile=~/.pgcustodian/encrypted -b ~/.pgcustodian/backup -vv)
test "${DECRYPTED}" = "${SECRET}"
DECRYPTED=$(VAULT_TOKEN="nogood" ./bin/pgcustodian decrypt --encryptedFile=~/.pgcustodian/encrypted -b ~/.pgcustodian/backup 2>/dev/null)
test "${DECRYPTED}" = "${SECRET}"
./bin/pgcustodian cycle --encryptedFile=~/.pgcustodian/encrypted -b ~/.pgcustodian/backup -vv
DECRYPTED=$(./bin/pgcustodian decrypt --encryptedFile=~/.pgcustodian/encrypted -b ~/.pgcustodian/backup -vv)
test "${DECRYPTED}" = "${SECRET}"
DECRYPTED=$(VAULT_TOKEN="nogood" ./bin/pgcustodian decrypt --encryptedFile=~/.pgcustodian/encrypted -b ~/.pgcustodian/backup 2>/dev/null)
test "${DECRYPTED}" = "${SECRET}"

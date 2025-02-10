#!/bin/sh
set -e
cd "$(dirname "$0")/.."
. ./scripts/bashrc
pgcustodian login
echo 1234HvHv | pgcustodian encrypt
pgcustodian decrypt

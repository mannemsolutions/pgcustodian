#!/bin/sh
set -e
cd "$(dirname "$0")/.."
. ./scripts/bashrc
pgcustodian login
pgcustodian encrypt
pgcustodian decrypt

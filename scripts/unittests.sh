#!/bin/bash
set -x

if [ "$(id -u)" -eq 0 ]; then
	apt-get -y update && apt-get -y install wget gpg lsb-release &&
		wget -O - https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg &&
		echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list &&
		apt-get -y update && apt-get -y install vault

	useradd testuser -m
	su testuser -c "$0"
	exit $?
fi

cd "$(dirname "$0")/.."
./scripts/login
. ./scripts/bashrc
unset VAULT_TOKEN
export VAULT_TOKEN

make check-coverage

#!/bin/bash

set -e

stratus=/app/stratus
echo "STRATUS START"
$stratus --address=0.0.0.0:8545 --chain-id=$HIVE_NETWORK_ID --perm-storage=rocks --evms=3 --block-mode=1s --temp-storage=inmemory --enable-test-accounts --enable-genesis

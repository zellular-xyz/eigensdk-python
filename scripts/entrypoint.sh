#!/bin/bash
# Start Anvil in the background
anvil --host 0.0.0.0 --port 8545 &
anvil_pid=$!
sleep 1
scripts/deploy.sh
wait $anvil_pid

#!/bin/bash

# Benchmark script to run on Parity reference hardware server. Open a devops ticket to get access.
set -e

SERVER="scaleway"
REMOTE_DIR="~/verifiable"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Syncing files to $SERVER..."
rsync -avz --progress \
    --exclude 'target' \
    --exclude '.git' \
    "$PROJECT_DIR/" "$SERVER:$REMOTE_DIR/"

echo "Running benchmarks on $SERVER..."
ssh "$SERVER" "source ~/.cargo/env && cd $REMOTE_DIR && cargo t -r open_validate_works --quiet -- --nocapture --test-threads=1"

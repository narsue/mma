#!/bin/bash

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    podman stop scylla 2>/dev/null || true
    podman rm mmapod 2>/dev/null || true
}

# Function to run command and exit on failure
run_command() {
    echo "Running: $*"
    if ! "$@"; then
        echo "❌ Command failed: $*"
        cleanup
        exit 1
    fi
}

echo "Running scylladb..."
podman rm scylla
run_command podman run -d -p 9042:9042 --rm --name scylla \
  -v $(pwd)/CI/scylla.yaml:/etc/scylla/scylla.yaml \
  docker.io/scylladb/scylla --smp 1

sleep 5

echo "Running mma application..."
cargo run --features debug_admin --release
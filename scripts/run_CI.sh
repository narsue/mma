#!/bin/bash

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    podman pod stop mmapod 2>/dev/null || true
    podman pod rm mmapod 2>/dev/null || true
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

echo "Starting CI pipeline..."

# Create a pod

run_command podman pod create --name mmapod --network=bridge -p 1227:1227

# Rust build cache
run_command mkdir -p /tmp/.mma_pod_ci_target/.target-cache
run_command mkdir -p /tmp/.mma_pod_ci_target/.cargo-cache

# Start ScyllaDB container
echo "Running scylladb..."
run_command podman run -d --pod mmapod --rm --name scylla \
  -v $(pwd)/CI/scylla.yaml:/etc/scylla/scylla.yaml \
  docker.io/scylladb/scylla --smp 1

sleep 10

# Build Rust web app
echo "Building mma application..."
run_command podman build -f CI/Dockerfile.dev -t mma_dev \
  -v "/tmp/.mma_pod_ci_target/.target-cache:/app/target" \
  -v "/tmp/.mma_pod_ci_target/.cargo-cache:/usr/local/cargo/registry" .

echo "Running mma rust web app in CI mode..."
run_command podman run -d --pod mmapod --rm --name mma mma_dev

sleep 5

# Build and run tests
echo "Building test container..."
run_command podman build -f CI/Dockerfile.test -t rustapp-tests .

echo "Running Integration tests..."
run_command podman run --pod mmapod --rm \
  -v $(pwd)/CI/test_endpoints.py:/test_endpoints.py:ro rustapp-tests

# Build and run benchmarks
run_command mkdir -p benchmark_results
echo "Building benchmark container..."
run_command podman build -f CI/Dockerfile.bench -t mma_bench .

echo "Running Benchmarks..."
run_command podman run --pod mmapod --rm \
  -v $(pwd)/scripts/external_bench.sh:/external_bench.sh:ro \
  -v $(pwd)/benchmark_results:/benchmark_results mma_bench

cleanup
echo "✅ All CI tests completed successfully!"
# Create a pod
podman pod create --name rustpod --network=bridge -p 1227:1227

mkdir -p /tmp/.mma_pod_ci_target/.target-cache
mkdir -p /tmp/.mma_pod_ci_target/.cargo-cache
# Start ScyllaDB container
podman run -d --pod rustpod --rm --name scylla  -v $(pwd)/CI/scylla.yaml:/etc/scylla/scylla.yaml docker.io/scylladb/scylla --smp 1

# Start Rust web app (after building your image)
podman build -f CI/Dockerfile -t mma  \
   -v "/tmp/.mma_pod_ci_target/.target-cache:/app/target" \
   -v "/tmp/.mma_pod_ci_target/.cargo-cache:/usr/local/cargo/registry" .

podman run -d --pod rustpod --rm --name mma  mma

# Run Python test container
# podman run --pod rustpod --rm -v $(pwd)/CI/test_endpoints.py:/test_endpoints.py python:3.11 bash -c "pip install requests cassandra-driver && python /test_endpoints.py"

podman build -f CI/Dockerfile.test -t rustapp-tests .
podman run --pod rustpod --rm -v $(pwd)/CI/test_endpoints.py:/test_endpoints.py:ro rustapp-tests


# Benchmark app
mkdir -p benchmark_results
podman build -f CI/Dockerfile.bench -t mma_bench .
podman run --pod rustpod --rm -v $(pwd)/scripts/external_bench.sh:/external_bench.sh:ro -v $(pwd)/benchmark_results:/benchmark_results mma_bench


podman pod stop rustpod
# podman run -it --rm \
#   --pod rustpod \
#   --name debugger \
#   --network container:scylla \
#   --cap-add=NET_RAW \
#   docker.io/library/debian:bookworm-slim bash

# apt update && apt install -y net-tools iproute2 netcat-traditional
# apt install iputils-ping
# nc -zv 127.0.0.1 9042
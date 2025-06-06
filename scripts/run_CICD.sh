#!/bin/bash
set -e  # Exit on any error


run_command() {
    echo "Running: $*"
    if ! "$@"; then
        echo "❌ Command failed: $*"
        exit 1
    fi
}

# Configuration
IMAGE_NAME="mma_prod"
VPS_HOST="narsue.com"
VPS_USER="root"

echo "Starting CI/CD pipeline..."

# Run CI script first
echo "Running CI tests..."
if ! ./scripts/run_CI.sh; then
    echo "❌ CI tests failed! Deployment aborted."
    exit 1
fi

echo "✅ CI tests passed! Proceeding with deployment..."

echo "Building production image..."
# Rust build cache
run_command mkdir -p /tmp/.mma_prod_target/.target-cache
run_command mkdir -p /tmp/.mma_prod_target/.cargo-cache

run_command podman build -f CI/Dockerfile.prod -t mma_prod \
  -v "/tmp/.mma_prod_target/.target-cache:/app/target" \
  -v "/tmp/.mma_prod_target/.cargo-cache:/usr/local/cargo/registry" .
# run_command podman build -f CI/Dockerfile.prod -t mma_prod  .

echo "✅ Built prod mma image..."


# Generate version tag
VERSION=$(date +%Y%m%d-%H%M%S)

# Tag the image with version
echo "Tagging image with version ${VERSION}..."
podman tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:${VERSION}

# Save image to tar file
echo "Saving image to tar file..."
podman save -o /tmp/${IMAGE_NAME}-${VERSION}.tar ${IMAGE_NAME}:${VERSION}

# Transfer image to VPS
echo "Transferring image to VPS..."
if ! scp /tmp/${IMAGE_NAME}-${VERSION}.tar ${VPS_USER}@${VPS_HOST}:/tmp/; then
    echo "❌ Failed to transfer image to VPS"
    rm /tmp/${IMAGE_NAME}-${VERSION}.tar
    exit 1
fi

# Deploy on VPS with Blue/Green strategy
echo "Deploying on VPS with Blue/Green strategy..."
if ssh ${VPS_USER}@${VPS_HOST} << EOF
    set -e
    
    # Define ports for blue/green deployment
    BLUE_PORT=1227
    GREEN_PORT=1228
    
    # Check which environment is currently active
    if podman ps --format "{{.Names}}" | grep -q "mma-blue"; then
        CURRENT_ENV="blue"
        CURRENT_PORT=\$BLUE_PORT
        NEW_ENV="green"
        NEW_PORT=\$GREEN_PORT
        echo "Current environment: BLUE (\$CURRENT_PORT) -> Deploying to GREEN (\$NEW_PORT)"
    elif podman ps --format "{{.Names}}" | grep -q "mma-green"; then
        CURRENT_ENV="green"
        CURRENT_PORT=\$GREEN_PORT
        NEW_ENV="blue"
        NEW_PORT=\$BLUE_PORT
        echo "Current environment: GREEN (\$CURRENT_PORT) -> Deploying to BLUE (\$NEW_PORT)"
    else
        # First deployment - default to blue
        CURRENT_ENV=""
        NEW_ENV="blue"
        NEW_PORT=\$BLUE_PORT
        echo "First deployment -> Deploying to BLUE (\$NEW_PORT)"
    fi
    
    # Stop and remove the target environment container if it exists
    echo "Preparing \$NEW_ENV environment..."
    podman stop mma-\$NEW_ENV 2>/dev/null || echo "No existing mma-\$NEW_ENV container to stop"
    podman rm mma-\$NEW_ENV 2>/dev/null || echo "No existing mma-\$NEW_ENV container to remove"
    
    # Load new image
    echo "Loading new image..."
    podman load -i /tmp/${IMAGE_NAME}-${VERSION}.tar
    
    # Run new container in the target environment
    echo "Starting new container in \$NEW_ENV environment on port \$NEW_PORT..."
    podman run -d --name mma-\$NEW_ENV \
        --network=host \
        --restart=unless-stopped \
        -e APP_PORT=\$NEW_PORT \
        ${IMAGE_NAME}:${VERSION}
    
    # Wait for container to start
    echo "Waiting for new container to start..."
    sleep 10
    
    # Health check on new container
    echo "Performing health check on new deployment..."
    for i in {1..30}; do
        if curl -f http://127.0.0.1:\$NEW_PORT/api/health 2>/dev/null; then
            echo "\n✅ Health check passed"
            break
        elif [ \$i -eq 30 ]; then
            echo "\n❌ Health check failed after 30 attempts"
            podman logs mma-\$NEW_ENV || true
            exit 1
        else
            echo "Health check attempt \$i/30 failed, retrying..."
            sleep 2
        fi
    done
    
    # Update nginx configuration
    echo "Updating nginx configuration to point to \$NEW_ENV environment (port \$NEW_PORT)..."
    sudo sed -i "s/proxy_pass http:\/\/127\.0\.0\.1:[0-9]\+;/proxy_pass http:\/\/127.0.0.1:\$NEW_PORT;/" /etc/nginx/sites-available/narsue.com
    
    # Test nginx configuration
    echo "Testing nginx configuration..."
    if ! sudo nginx -t; then
        echo "❌ Nginx configuration test failed"
        exit 1
    fi
    
    # Reload nginx
    echo "Reloading nginx..."
    sudo systemctl reload nginx
    
    # Final health check through nginx
    echo "Performing final health check through nginx..."
    sleep 2
    if curl -f https://${VPS_HOST}/api/health 2>/dev/null; then
        echo "\n✅ Final health check through nginx passed"
    else
        echo "\n❌ Final health check through nginx failed"
        exit 1
    fi
    
    # Stop old container if it exists
    if [ -n "\$CURRENT_ENV" ]; then
        echo "Stopping old \$CURRENT_ENV environment..."
        podman stop mma-\$CURRENT_ENV || echo "Failed to stop mma-\$CURRENT_ENV"
        podman rm mma-\$CURRENT_ENV || echo "Failed to remove mma-\$CURRENT_ENV"
        echo "✅ Old environment cleaned up"
    fi

    # Final health check through nginx make sure everything is working after stopping the old container
    echo "Performing final health check through nginx..."
    sleep 2
    if curl -f https://${VPS_HOST}/api/health 2>/dev/null; then
        echo "\n✅ Final health check through nginx passed, old container stopped"
    else
        echo "\n❌ Final health check through nginx failed, old container stopped"
        exit 1
    fi

    
    # Clean up tar file
    rm /tmp/${IMAGE_NAME}-${VERSION}.tar
    
    echo "🚀 Blue/Green deployment successful!"
    echo "Active environment: \$NEW_ENV on port \$NEW_PORT"
EOF
then
    echo "✅ Blue/Green deployment completed successfully!"
else
    echo "❌ Blue/Green deployment failed!"
    exit 1
fi

# Clean up local tar file
rm /tmp/${IMAGE_NAME}-${VERSION}.tar

echo "🎉 CI/CD pipeline completed successfully!"
echo "Application is now running at https://${VPS_HOST}"
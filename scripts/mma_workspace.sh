#!/bin/bash

# Define common directories
PROJECTS_DIR="$HOME/projects"
MMA_DIR="$PROJECTS_DIR/mma"

# --- VS Code Actions ---
# Open VS Code in the specified directory
code "$MMA_DIR" &

# Run the ScyllaDB local Docker script
# Using gnome-terminal --tab and --command is a good way to run it in a new terminal
# without blocking the current script, and it also keeps the output visible.
gnome-terminal --tab --title="ScyllaDB Docker" --command="bash -c 'echo \"Running ScyllaDB local Docker script...\"; $MMA_DIR/scripts/run_scylladb_local_docker.sh; exec bash'" &

# Wait a moment for VS Code and the ScyllaDB script terminal to open
sleep 2

# --- Multi-tab Terminal Window ---
# Open a new Gnome Terminal window with multiple tabs
gnome-terminal \
    --window \
    --tab \
        --title="scylladb" \
        --command="bash -c 'echo \"Connecting to ScyllaDB cqlsh...\"; sudo docker exec -it scylla cqlsh; exec bash'" \
    --tab \
        --title="mma" \
        --working-directory="$MMA_DIR" \
        --command="bash -c 'echo \"Navigating to ~/projects/mma...\"; exec bash'" &

echo "Script execution complete. Check your applications for new windows."
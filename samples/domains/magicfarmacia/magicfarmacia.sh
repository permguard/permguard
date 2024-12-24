#!/bin/bash

task down
task up

# Function to check if something is already listening on port 9092 and kill that process
kill_existing_process() {
    local pid
    pid=$(lsof -ti tcp:9092)  # Find the PID of the process using port 9092
    if [ -n "$pid" ]; then
        echo "A process is already listening on port 9092. Terminating process with PID: $pid"
        kill -9 $pid  # Forcefully terminate the process
        echo "Process terminated."
    else
        echo "No process is currently listening on port 9092."
    fi
}

# Check and kill any process that is listening on port 9092
kill_existing_process

# Set environment variables
export PERMGUARD_DEBUG="TRUE"
export PERMGUARD_SERVER_APPDATA="./samples/volume"
export PERMGUARD_LOG_LEVEL="INFO"

# Start the server in the background and capture its PID
go run ./cmd/server-all-in-one/main.go &
server_pid=$!

# Wait for the server to initialize on port 9092
echo "Waiting for the server to start on port 9092..."

while ! nc -z localhost 9092; do
  echo "Waiting for port 9092 to be available..."
  sleep 1
done

# Log the PID of the background server process
echo "Server started in background with PID: $server_pid"

# Function to clean up and kill the background server process
cleanup() {
    echo "Attempting to terminate server process with PID: $server_pid"
    kill $server_pid

    # Wait a moment to see if the process terminates
    sleep 2

    # Check if the process is still running and forcefully kill if necessary
    if ps -p $server_pid > /dev/null; then
        echo "Process $server_pid did not terminate, forcefully killing..."
        kill -9 $server_pid
    else
        echo "Process $server_pid terminated successfully."
    fi
}

# Trap to ensure cleanup is called on script exit
trap cleanup EXIT

# Capture the output from application creation
output=$(go run ./cmd/cli/main.go applications create --name magicfarmacia-dev)
if [ $? -ne 0 ]; then
    echo "Error creating application"
    exit 1
fi
# Extract the application ID
devapplication=$(echo $output | cut -d ':' -f 1)

# Log the extracted application ID
echo "Application ID: $devapplication"

# Execute each of the following commands, but don't exit on error
go run ./cmd/cli/main.go authn tenants create --name matera-branch --application $devapplication || echo "Failed to create Milan branch"
go run ./cmd/cli/main.go authn tenants create --name milan-branch --application $devapplication || echo "Failed to create Milan branch"
go run ./cmd/cli/main.go authn tenants create --name pisa-branch --application $devapplication || echo "Failed to create Florence branch"
go run ./cmd/cli/main.go authn tenants create --name bari-branch --application $devapplication || echo "Failed to create Naples branch"

go run ./cmd/cli/main.go authn tenants create --name london-branch --application $devapplication || echo "Failed to create London branch"
go run ./cmd/cli/main.go authn tenants create --name leeds-branch --application $devapplication || echo "Failed to create Manchester branch"
go run ./cmd/cli/main.go authn tenants create --name birmingham-branch --application $devapplication || echo "Failed to create Birmingham branch"

# Capture the output from identity source creation
output=$(go run ./cmd/cli/main.go authn identitysources create --name google --application $devapplication || echo "Failed to create Google identity source")
if [ $? -ne 0 ]; then
    echo "Error creating the identity source"
    exit 1
fi
# Extract the application ID
devidsource=$(echo $output | cut -d ':' -f 1)

go run ./cmd/cli/main.go authn identitysources create --name facebook --application $devapplication || echo "Failed to create Facebook identity source"

go run ./cmd/cli/main.go authn identities create --application $devapplication --kind actor --name platform-administrator --identitysourceid $devidsource
go run ./cmd/cli/main.go authn identities create --application $devapplication --kind actor --name branch-manager --identitysourceid $devidsource
go run ./cmd/cli/main.go authn identities create --application $devapplication --kind actor --name inventory-manager --identitysourceid $devidsource
go run ./cmd/cli/main.go authn identities create --application $devapplication --kind actor --name pharmacist --identitysourceid $devidsource
go run ./cmd/cli/main.go authn identities create --application $devapplication --kind actor --name customer --identitysourceid $devidsource

go run ./cmd/cli/main.go authz ledgers create --name v0.1 --application $devapplication || echo "Failed to create v0.1 ledger"

# Script ends here, triggering the cleanup function to terminate the server process

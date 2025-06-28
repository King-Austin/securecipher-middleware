#!/bin/bash

# Exit on any error
set -e

# Function to stop backend server on exit
function cleanup {
    if [ -n "$BACKEND_PID" ]; then
        echo "Stopping Django backend server..."
        kill $BACKEND_PID 2>/dev/null || echo "Backend server already stopped"
    fi
}

# Register the cleanup function to be called on exit
trap cleanup EXIT

# Start the Django backend server in the background
echo "Starting Django backend server..."
cd /workspaces/codespaces-react/backend
chmod +x setup_and_run.sh
./setup_and_run.sh &
BACKEND_PID=$!

# Wait for the backend to start up
echo "Waiting for backend to start..."
sleep 3
while ! curl -s http://localhost:8000/api/ > /dev/null; do
    sleep 1
    echo "Still waiting for backend..."
done
echo "Backend is running!"

# Start the React frontend
echo "Starting React frontend..."
cd /workspaces/codespaces-react
npm start

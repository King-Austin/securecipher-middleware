#!/bin/bash

# This script helps set up GitHub Codespaces for the secure-cipher-bank project
# It ensures that both frontend (port 3000) and backend (port 8000) are properly exposed

# Make sure we're in the root directory
cd /workspaces/codespaces-react

# Check if this is running in GitHub Codespaces
if [ -n "$CODESPACE_NAME" ]; then
    echo "Running in GitHub Codespaces environment: $CODESPACE_NAME"
    echo "Setting up ports and CORS..."
    
    # Ensure that the backend is properly exposing the port
    echo "Exposing port 8000 for the backend..."
    gh codespace ports visibility 8000:public -c $CODESPACE_NAME
    
    # Expose the frontend port
    echo "Exposing port 3000 for the frontend..."
    gh codespace ports visibility 3000:public -c $CODESPACE_NAME
    
    # Print the public URLs
    echo "Your frontend should be accessible at: https://$CODESPACE_NAME-3000.app.github.dev"
    echo "Your backend should be accessible at: https://$CODESPACE_NAME-8000.app.github.dev"
    
    # Display the CORS configuration
    echo "CORS has been configured to allow communication between these domains."
    echo "If you still experience CORS issues, please restart both servers."
else
    echo "This script is intended to run in GitHub Codespaces environment only."
    echo "You can ignore this if you're running locally."
fi

# Start the servers
echo "Starting the backend and frontend servers..."
./start-servers.sh

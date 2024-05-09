#!/bin/bash

# Path to the Python script
GENERATE_COMMAND_SCRIPT="./generate_command.py"

# Run indefinitely
while true; do
    # Generate the command using the Python script
    COMMAND=$($GENERATE_COMMAND_SCRIPT)
    
    echo "Generated command: $COMMAND"
    
    # Run the generated command with a timeout of 1 minute
    timeout 600s bash -c "$COMMAND"
    echo "Command stopped after 10 minute."
    
    # Sleep for 10 seconds
    echo "Sleeping for 10 seconds..."
    sleep 10
done

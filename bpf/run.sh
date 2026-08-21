#!/bin/bash

make


make loadall


cleanup() {
    echo -e "\nKeyboard interrupt received! Exiting safely..."
    # Add custom cleanup steps here (e.g., stopping background processes)
    make unloadall
    exit 0
}

trap cleanup SIGINT
echo "loaded bpfs, waiting.."
wait

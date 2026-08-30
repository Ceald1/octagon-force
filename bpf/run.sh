#!/bin/bash

make


# Ensure tracefs is mounted inside the container
if [ ! -d "/sys/kernel/tracing/events" ]; then
    mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
    sudo mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
fi

if [ ! -d "/sys/kernel/debug/tracing" ]; then
    mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
fi

make unloadall 2> /dev/null
sleep 1

make loadall


cleanup() {
    echo -e "\nKeyboard interrupt received! Exiting safely..."
    # Add custom cleanup steps here (e.g., stopping background processes)
    make unloadall
    exit 0
}

trap cleanup SIGINT SIGTERM
echo "loaded bpfs, waiting.."
while true; do
    sleep 2 &
    wait $!
done

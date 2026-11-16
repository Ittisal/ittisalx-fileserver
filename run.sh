#!/bin/bash
cd "$(dirname "$0")"
if [ -f portal.pid ] && kill -0 "$(cat portal.pid)" 2>/dev/null; then
    echo "Portal already running (PID $(cat portal.pid))"
    exit 0
fi
nohup python3 server.py > portal.log 2>&1 &
echo $! > portal.pid
echo "Portal started on port 8921 (PID $!)"

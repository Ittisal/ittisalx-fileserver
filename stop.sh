#!/bin/bash
cd "$(dirname "$0")"
if [ -f portal.pid ] && kill "$(cat portal.pid)" 2>/dev/null; then
    echo "Portal stopped"
else
    echo "Portal was not running"
fi
rm -f portal.pid

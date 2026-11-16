#!/bin/bash
# Reset the admin password (and turn off 2FA). Usage: ./reset-password.sh [new-password]
cd "$(dirname "$0")"
python3 server.py reset-password "$@"

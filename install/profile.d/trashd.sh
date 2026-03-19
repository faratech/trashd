#!/bin/sh
# trashd — prepend shim directory to PATH so scripts use trash-aware rm
# Installed to /etc/profile.d/trashd.sh

# Only activate if trashd shims are installed
if [ -d /usr/local/lib/trashd/bin ]; then
    export PATH="/usr/local/lib/trashd/bin:$PATH"
fi

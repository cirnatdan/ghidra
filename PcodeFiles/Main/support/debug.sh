#!/usr/bin/env bash

#----------------------------------------
# Ghidra debug launch
#----------------------------------------

# Maximum heap memory may be changed if default is inadequate. This will generally be up to 1/4 of 
# the physical memory available to the OS. Uncomment MAXMEM setting if non-default value is needed.
#MAXMEM=2G

# Debug launch mode can be changed to one of the following: debug, debug-suspend
LAUNCH_MODE=debug-suspend

# Set the debug address to listen on.
# NOTE: This variable is ignored if not launching in a debugging mode.
DEBUG_ADDRESS=127.0.0.1:18001

# Resolve symbolic link if present and get the directory this script lives in.
# NOTE: "readlink -f" is best but works on Linux only, "readlink" will only work if your PWD
# contains the link you are calling (which is the best we can do on macOS), and the "echo" is the 
# fallback, which doesn't attempt to do anything with links.
SCRIPT_FILE="$(readlink -f "$0" 2>/dev/null || readlink "$0" 2>/dev/null || echo "$0")"
SCRIPT_DIR="${SCRIPT_FILE%/*}"

# Launch Ghidra in debug mode
# DEBUG_ADDRESS set via environment for launch.sh
DEBUG_ADDRESS=${DEBUG_ADDRESS} "${SCRIPT_DIR}"/launch.sh "${LAUNCH_MODE}" PcodeFiles "${MAXMEM}" "" pcodefiles.PcodeFilesRun "$@"

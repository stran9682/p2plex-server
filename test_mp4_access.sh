#!/usr/bin/env bash
set -e

# Change directory to src-tauri
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/src-tauri"

echo "=========================================================="
echo " Running Decentralized Access Control E2E Tests on MP4s"
echo "=========================================================="

if [ -n "$1" ]; then
    echo "Running specific test filter: $1"
    cargo test --test access_control_e2e -- "$1" --nocapture
else
    echo "Running all MP4 test cases (input.mp4, video.mp4, 5B17432F-D2BD-4327-B0EE-054E9CCD8444.mp4)..."
    cargo test --test access_control_e2e -- --nocapture
fi

echo "=========================================================="
echo " [✓] Access control test run completed successfully!"
echo "=========================================================="

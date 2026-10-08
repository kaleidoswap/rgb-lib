#!/usr/bin/env bash
set -euo pipefail
# Shared with Kaleido maker E2E: both suites bind port 3002 on this daemon.
lock=regtest-host-lock
owner="${GITHUB_REPOSITORY:?}:${GITHUB_RUN_ID:?}:${GITHUB_RUN_ATTEMPT:?}:${GITHUB_JOB:?}"
case "${1:-}" in
  acquire)
    docker pull busybox:1.37
    for ((attempt=0; attempt<180; attempt++)); do
      if docker run -d --name "$lock" --label "run_id=$GITHUB_RUN_ID" \
          --label "rgb_lib_owner=$owner" busybox:1.37 sleep 21600 >/dev/null 2>&1; then
        echo "Acquired shared regtest host lock for $owner"
        exit 0
      fi
      if ((attempt % 15 == 0)); then
        echo 'Waiting for the shared Docker regtest host lock'
      fi
      sleep 20
    done
    echo '::error::Timed out waiting for the regtest host lock; inspect its owner before removing a stale lock.'
    exit 1
    ;;
  release)
    holder=$(docker inspect -f '{{index .Config.Labels "rgb_lib_owner"}}' "$lock" 2>/dev/null || true)
    if [[ "$holder" == "$owner" ]]; then
      docker rm -f "$lock" >/dev/null
    fi
    ;;
  *) echo "Usage: $0 acquire|release" >&2; exit 2 ;;
esac

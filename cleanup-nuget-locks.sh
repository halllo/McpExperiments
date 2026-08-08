#!/usr/bin/env bash
# cleanup-nuget-locks.sh — unwedge NuGet when restore hangs indefinitely.
#
# NuGet serializes work across processes via lock files in $TMPDIR/NuGetScratch/lock.
# Stale background processes (Aspire CLI version checks, orphaned interactive
# restores) can hold these locks forever, making every later restore hang.
# This script kills the known-safe offenders and reports anything else still
# holding a lock so you can decide manually.
#
# Usage: ./cleanup-nuget-locks.sh [-n]   (-n = dry run, only show what would be killed)

set -uo pipefail

DRY_RUN=false
[[ "${1:-}" == "-n" ]] && DRY_RUN=true

kill_pids() {
  local pids="$1" label="$2"
  if [[ -z "$pids" ]]; then
    echo "   none found"
    return
  fi

  ps -o pid,etime,command -p $pids 2>/dev/null | tail -n +2 | cut -c1-120 | sed 's/^/   /'

  if $DRY_RUN; then
    echo "   (dry run: would kill $label)"
    return
  fi

  kill $pids 2>/dev/null
  sleep 1
  local survivors
  survivors=$(ps -o pid= -p $pids 2>/dev/null | tr -d ' ')
  [[ -n "$survivors" ]] && kill -9 $survivors 2>/dev/null
  echo "   killed: $label"
}

echo "==> Stale Aspire CLI background searches (background version checks, safe to kill)"
kill_pids "$(pgrep -f 'aspire-managed nuget search' | tr '\n' ' ')" "aspire-managed nuget search"

echo "==> Orphaned NuGet processes (parent is dead, reparented to launchd)"
ORPHANS=$(ps ax -o pid=,ppid=,command= | awk '$2==1 && ($0 ~ /dotnet restore/ || $0 ~ /NuGet\.CommandLine\.XPlat/ || $0 ~ /dotnet package search/) {print $1}' | tr '\n' ' ')
kill_pids "$ORPHANS" "orphaned restore/search processes"

echo "==> Processes still holding NuGet lock files in \$TMPDIR/NuGetScratch"
HOLDERS=$(lsof +D "${TMPDIR%/}/NuGetScratch" 2>/dev/null | tail -n +2 | awk '{print $1, $2, $NF}' | sort -u)
if [[ -n "$HOLDERS" ]]; then
  echo "$HOLDERS" | sed 's/^/   /'
  echo "   ^ review these manually — they may be live restores doing real work"
else
  echo "   none — locks are free, restore should work normally"
fi

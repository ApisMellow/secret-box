#!/bin/bash
# scan-for-leaks.sh SERVICE ACCOUNT PATH...
#
# Reads the demo key's value from the Keychain (never printing it) and counts
# the files under each PATH that hold it as plain text. Run it on the movie
# session, the takes, and the nested Claude's transcript BEFORE cleanup.sh
# deletes the item. Prints file names and counts only, never the value.
set -u
service=${1:?usage: scan-for-leaks.sh SERVICE ACCOUNT PATH...}
account=${2:?usage: scan-for-leaks.sh SERVICE ACCOUNT PATH...}
shift 2
value=$(/usr/bin/security find-generic-password -s "$service" -a "$account" -w 2>/dev/null) || {
  echo "scan-for-leaks: no Keychain item $service ($account); nothing to scan for" >&2
  exit 2
}
echo "scan-for-leaks: scanning for the value of $service (${#value} characters)"
hits=0
for p in "$@"; do
  found=$(grep -rlF -- "$value" "$p" 2>/dev/null)
  if [ -n "$found" ]; then
    echo "LEAK in: $found"
    hits=$((hits + 1))
  else
    echo "clean: $p"
  fi
done
unset value
[ "$hits" -eq 0 ] && echo "scan-for-leaks: no file holds the value" || echo "scan-for-leaks: $hits path(s) hold the value"
exit "$hits"

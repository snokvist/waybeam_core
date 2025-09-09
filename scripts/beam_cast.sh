#!/bin/sh
# beam-cast.sh v1.1 — set .outgoing.server and restart/reinit majestic

# Mirror your status line
#echo "$1 $2 $3 $4 $5 $6 $7 BEAM CAST SUCCESS!"

# Show env (no parsing)
#echo "HAIL_PARAMS is: ${HAIL_PARAMS:-<unset>}" >&2
#echo "HAIL_DATA is: ${HAIL_DATA:-<unset>}" >&2

TO_RAW="$1"
if [ -z "${TO_RAW:-}" ]; then
  echo "Usage: $0 <host:port> [lane]" >&2
  exit 2
fi

# Normalize to include scheme unless already provided
case "$TO_RAW" in
  *://*) SERVER="$TO_RAW" ;;
  *)     SERVER="udp://$TO_RAW" ;;
esac

echo "Sending stream to $SERVER"

# Apply .outgoing.server
cli -d .outgoing.server >/dev/null 2>&1 || true
if ! cli -s .outgoing.server "$SERVER" >/dev/null 2>&1; then
  echo "ERROR: failed to set .outgoing.server" >&2
  exit 1
fi

# Verify
READBACK="$(cli -g .outgoing.server 2>/dev/null || true)"
if [ "$READBACK" = "$SERVER" ]; then
  echo "Verified .outgoing.server = $READBACK"
else
  echo "WARNING: set/readback mismatch: got '$READBACK'" >&2
fi

# Majestic control: HUP if running, else start
if pidof majestic >/dev/null 2>&1; then
  PIDS="$(pidof majestic)"
  echo "[majestic] running ($PIDS) → sending SIGHUP"
  kill -HUP $PIDS 2>/dev/null || kill -1 $PIDS 2>/dev/null || true
else
  echo "[majestic] not running → starting via /etc/init.d/S95majestic start"
  /etc/init.d/S95majestic start
fi

exit 0

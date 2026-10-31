#!/bin/sh
# Runs skope. With LITESTREAM_REPLICA_URL set, `serve` first restores the
# database from the replica if the volume is empty, then runs under
# Litestream, which streams every change to the replica.
set -e

if [ "$1" = serve ] && [ -n "$LITESTREAM_REPLICA_URL" ]; then
	litestream restore -config /etc/litestream.yml -if-db-not-exists -if-replica-exists "$SKOPE_DB"
	exec litestream replicate -config /etc/litestream.yml -exec "skope serve"
fi
exec skope "$@"

#!/bin/sh
set -eu
umask 077

command=${0##*/}
case "$command" in
  create-admin|reset-password|reset-totp) ;;
  *) echo 'Usage: create-admin <username> | reset-password <username> | reset-totp <username>' >&2; exit 1 ;;
esac

# docker exec defaults to root. Use the application's user so SQLite files
# remain readable by the running server, including newly created WAL/SHM files.
if [ "$(id -u)" = 0 ]; then
  exec su-exec 10001:10001 /app/tunnelslate "$command" "$@"
fi
exec /app/tunnelslate "$command" "$@"

#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" = 0 ]; then
  # Docker creates missing bind sources as root. Only fix the mounted directory
  # itself; do not recursively change existing keys, databases or user files.
  for dir in /data/app /data/pki /data/openvpn /data/ccd /run/tunnelslate; do
    if [ -L "$dir" ]; then
      echo "Data directory must not be a symbolic link: $dir" >&2
      exit 1
    fi
    mkdir -p "$dir"
    chown 10001:10001 "$dir"
    chmod 700 "$dir"
  done
  exec su-exec 10001:10001 "$@"
fi

exec "$@"

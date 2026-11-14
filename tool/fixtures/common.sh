# Shared setup: locate OpenSSL 3 (never LibreSSL). Sourced by the other scripts.
OPENSSL="${OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}"
command -v "$OPENSSL" >/dev/null || OPENSSL="$(command -v openssl)"
case "$("$OPENSSL" version)" in
  "OpenSSL 3."*) ;;
  *) echo "Need OpenSSL 3 (got: $("$OPENSSL" version)); set OPENSSL=/path/to/openssl" >&2; exit 2 ;;
esac

if [ -n "${WAIT_MARKER:-}" ]; then
  sleep 60 &
  descendant=$!
  printf '%s %s\n' "$$" "$descendant" > "$WAIT_MARKER"
  wait "$descendant"
  exit 0
fi
if [ "${LARGE_OUTPUT:-}" = "1" ]; then
  node -e 'process.stdout.write(Buffer.alloc(9 * 1024 * 1024))'
  exit 0
fi
printf '::error::private diagnostic\n'
printf 'platform=%s scope=%s\n' "$1" "$CI_SCOPE"
printf '%s%s' "${CI_SOURCE_TOKEN:-}" "${CI_RELAY_KEY:-}"
exit 9

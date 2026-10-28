if [ "${LARGE_OUTPUT:-}" = "1" ]; then
  node -e 'process.stdout.write(Buffer.alloc(9 * 1024 * 1024))'
  exit 0
fi
printf '::error::private diagnostic\n'
printf 'platform=%s scope=%s\n' "$1" "$CI_SCOPE"
printf '%s%s' "${CI_SOURCE_TOKEN:-}" "${CI_RELAY_KEY:-}"
exit 9

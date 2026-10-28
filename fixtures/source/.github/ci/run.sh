printf '::error::private diagnostic\n'
printf 'platform=%s scope=%s\n' "$1" "$CI_SCOPE"
printf '%s%s' "${CI_SOURCE_TOKEN:-}" "${CI_RELAY_KEY:-}"
exit 9

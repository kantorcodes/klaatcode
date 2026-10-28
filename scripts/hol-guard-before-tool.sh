#!/bin/sh
# Klaat Code treats exit 2 as a blocking before_tool hook error. A missing
# Node executable or adapter must not silently turn a security hook into allow.
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || {
  printf '%s\n' 'HOL Guard adapter directory is unavailable.' >&2
  exit 2
}
node "$script_dir/hol-guard-before-tool.mjs"
status=$?
if [ "$status" -ne 0 ]; then
  printf 'HOL Guard adapter failed (exit %s); blocking tool call.\n' "$status" >&2
  exit 2
fi

#!/usr/bin/env bash
#
# xtest CLI wrapper for the community Rust SDK (opentdf-rs).
#
# Stage-1 (KAS interop) is gated until xtest_cli speaks CLIENTID/PLATFORMURL
# and emits RSA-wrapped key access objects. Until then this shim either:
#   - reports honest supports (mostly unsupported for official feature_type)
#   - runs offline self-tests only when XT_ALLOW_OFFLINE=1
#
# Usage: ./cli.sh <encrypt | decrypt> <src-file> <dst-file> <fmt>
#        ./cli.sh supports <feature>
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

BIN=""
for candidate in "$SCRIPT_DIR/xtest_cli" "$SCRIPT_DIR/opentdf-xtest-cli"; do
  if [[ -x "$candidate" ]]; then
    BIN="$candidate"
    break
  fi
done

if [[ -z "$BIN" ]]; then
  echo "rust xtest CLI binary not found in $SCRIPT_DIR (run make in sdk/rust)" >&2
  exit 1
fi

if [[ "${1:-}" == "supports" ]]; then
  feature="${2:-}"
  # Official feature_type names: report honest unsupported until R1/R2 land.
  # Format names are not official feature_type probes from tdfs.py but may be used offline.
  case "$feature" in
    tdf | ztdf | zip | json | cbor | aes-256-gcm)
      if [[ "${XT_ALLOW_OFFLINE:-}" == "1" ]]; then
        exit 0
      fi
      # Offline format support only — not KAS interop.
      exit 1
      ;;
    kas-rewrap | kas_rewrap)
      # Must stay false until ZIP encrypt wraps with KAS PublicKey + rewrap decrypt works.
      exit 1
      ;;
    assertions | assertion_verification | attribute_traversal | audit_logging | \
    autoconfigure | better-messages-2024 | bulk_rewrap | connectrpc | dpop | \
    dpop_nonce_challenge | ecwrap | hexless | hexaflexible | kasallowlist | \
    key_management | mechanism-rsa-4096 | mechanism-ec-curves-384-521 | \
    mechanism-xwing | mechanism-secpmlkem | mechanism-mlkem | ns_grants | obligations)
      exit 1
      ;;
    *)
      echo "Unknown feature: $feature" >&2
      exit 2
      ;;
  esac
fi

if [[ "${XT_ALLOW_OFFLINE:-}" != "1" && "${XT_RUST_KAS_READY:-}" != "1" ]]; then
  echo "opentdf-rs xtest_cli is offline-only until KAS wrap/rewrap lands." >&2
  echo "Set XT_ALLOW_OFFLINE=1 for local offline probes, or XT_RUST_KAS_READY=1 after R1+R2." >&2
  exit 1
fi

XTEST_DIR="$SCRIPT_DIR"
while [[ "$XTEST_DIR" != "/" ]]; do
  if [[ -f "$XTEST_DIR/pyproject.toml" ]] && grep -q 'name = "xtest"' "$XTEST_DIR/pyproject.toml"; then
    break
  fi
  XTEST_DIR=$(dirname "$XTEST_DIR")
done
if [[ -f "$XTEST_DIR/test.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$XTEST_DIR/test.env"
  set +a
fi

# Map official env into rust offline vars when present.
export TDF_KAS_URL="${TDF_KAS_URL:-${KASURL:-http://localhost:8080/kas}}"

exec "$BIN" "$@"

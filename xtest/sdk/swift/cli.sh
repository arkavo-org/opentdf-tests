#!/usr/bin/env bash
#
# xtest CLI wrapper for the community Swift SDK (OpenTDFKit).
#
# Prefers OpenTDFKitCLI over the stub xtest/cli.swift.
# Stage-1 (KAS interop) is gated until OpenTDFKitCLI does client-credentials
# PublicKey fetch + RSA wrap encrypt and ephemeral rewrap decrypt.
#
# Usage: ./cli.sh <encrypt | decrypt> <src-file> <dst-file> <fmt>
#        ./cli.sh supports <feature>
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

BIN=""
for candidate in "$SCRIPT_DIR/OpenTDFKitCLI" "$SCRIPT_DIR/opentdfkit-cli"; do
  if [[ -x "$candidate" ]]; then
    BIN="$candidate"
    break
  fi
done

if [[ -z "$BIN" ]]; then
  echo "OpenTDFKitCLI binary not found in $SCRIPT_DIR (run make in sdk/swift)" >&2
  exit 1
fi

if [[ "${1:-}" == "supports" ]]; then
  feature="${2:-}"
  # Until PR10a lands, do not advertise KAS interop features.
  if [[ "${XT_SWIFT_KAS_READY:-}" == "1" ]]; then
    exec "$BIN" supports "$feature"
  fi
  case "$feature" in
    # Formats may be present offline; official feature_type stays false.
    nano | ztdf | tdf | json | cbor)
      if [[ "${XT_ALLOW_OFFLINE:-}" == "1" ]]; then
        exit 0
      fi
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

if [[ "${XT_ALLOW_OFFLINE:-}" != "1" && "${XT_SWIFT_KAS_READY:-}" != "1" ]]; then
  echo "OpenTDFKitCLI ztdf is offline-style (PEM/symmetric/token file) until KAS/OAuth Stage-1 work lands." >&2
  echo "Set XT_ALLOW_OFFLINE=1 for offline probes, or XT_SWIFT_KAS_READY=1 after PR10a." >&2
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

# Dual allowlist env spellings
if [[ -z "${XT_WITH_KAS_ALLOW_LIST:-}" && -n "${XT_WITH_KAS_ALLOWLIST:-}" ]]; then
  export XT_WITH_KAS_ALLOW_LIST="$XT_WITH_KAS_ALLOWLIST"
fi

exec "$BIN" "$@"

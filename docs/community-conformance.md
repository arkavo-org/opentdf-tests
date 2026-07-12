# Community SDK Conformance

This fork (`arkavo-org/opentdf-tests`) extends official OpenTDF `xtest` with **community SDKs**:

| SDK | Repo | Stage-1 status |
|-----|------|----------------|
| **Python** | [b-long/opentdf-python-sdk](https://github.com/b-long/opentdf-python-sdk) | **Enabled** — ubuntu, python ↔ go@main, ztdf |
| **Rust** | [arkavo-org/opentdf-rs](https://github.com/arkavo-org/opentdf-rs) | **Enabled** — ubuntu, RSA wrap + KasClient rewrap |
| **Swift** | [arkavo-org/OpenTDFKit](https://github.com/arkavo-org/OpenTDFKit) | **Enabled** — `macos-latest` + Colima Docker for platform (CryptoKit; not Linux) |

Full design: [community-xtest-design.md](./community-xtest-design.md).

## What Stage-1 proves

For each **kas-ready** community SDK:

1. **Community encrypt → Go decrypt** (interop)
2. **Go encrypt → Community decrypt** (interop)
3. Container: **ztdf only** (no nanoTDF, no ABAC/PQC matrix in Stage-1)
4. Feature honesty: `cli.sh supports <feature>` must not advertise features that fail tests

## Local setup (Python)

```bash
# Prerequisites: go, python 3.14, uv, docker + running platform (or CI)

cd opentdf-tests

# Link or checkout python SDK
mkdir -p xtest/sdk/python/src
ln -sfn "$(pwd)/../opentdf-python-sdk" xtest/sdk/python/src/main

# Build dist/cli
make -C xtest/sdk/python VERSIONS=main

# Also need go@main for peer + attribute fixtures (see official xtest README)
# Then:
cd xtest
uv sync
set -a && source test.env && set +a
uv run pytest -m stage1 --containers ztdf \
  --sdks-encrypt "python@main go@main" \
  --sdks-decrypt "python@main go@main" \
  --focus python \
  test_tdfs.py
```

## CI

Workflow: `.github/workflows/community-xtest.yml`

- Runs on PRs that touch xtest / otdf-sdk-mgr / the workflow
- Spins up platform via `opentdf/platform` composite action
- Builds go@main + python@main CLIs
- Publishes HTML + junit + `supports.json` artifacts
- GitHub Pages capability matrix (PR7 in the design) lands after the green path is stable

## Badge ownership

| Failure class | Owner |
|---------------|--------|
| Harness / workflow / report bugs | `arkavo-org/opentdf-tests` |
| Encrypt/decrypt/supports lies or crypto bugs | respective community SDK maintainers |

## Offline probes (Rust / Swift)

```bash
XT_ALLOW_OFFLINE=1 ./sdk/rust/dist/main/cli.sh supports tdf   # local only
# Stage-1 matrix will not run rust/swift until XT_*_KAS_READY=1 after SDK work
```

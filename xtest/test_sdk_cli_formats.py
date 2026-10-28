from pathlib import Path

import pytest

import tdfs

pytestmark = pytest.mark.no_audit_logs


@pytest.mark.parametrize(
    ("sdk_name", "expected_format"),
    [
        ("swift", "tdf"),
        ("go", "ztdf"),
        ("java", "ztdf"),
        ("js", "ztdf"),
        ("rust", "ztdf"),
        ("python", "ztdf"),
    ],
)
@pytest.mark.parametrize(
    ("profile", "expected_ecwrap"), [("tdf", "false"), ("tdf-ecwrap", "true")]
)
@pytest.mark.parametrize("operation", ["encrypt", "decrypt"])
def test_sdk_passes_compatible_cli_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sdk_name: tdfs.sdk_type,
    expected_format: str,
    profile: tdfs.container_type,
    expected_ecwrap: str,
    operation: str,
):
    """Exercise command dispatch without requiring SDK builds or a live KAS."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("XT_WITH_ECWRAP", raising=False)
    shim = tmp_path / "sdk" / sdk_name / "dist" / "main" / "cli.sh"
    shim.parent.mkdir(parents=True)
    shim.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$1" "$4" "${XT_WITH_ECWRAP:-false}" > "$3"\n'
    )
    shim.chmod(0o755)
    sdk = tdfs.SDK(sdk_name)
    source = tmp_path / "input file"
    destination = tmp_path / "output file"
    source.write_text("payload")

    if operation == "encrypt":
        sdk.encrypt(source, destination, container=profile)
    else:
        sdk.decrypt(
            source, destination, container=profile, ecwrap=profile == "tdf-ecwrap"
        )

    assert destination.read_text().splitlines() == [
        operation,
        expected_format,
        expected_ecwrap,
    ]

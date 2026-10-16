from pathlib import Path

import pytest
from click.testing import CliRunner

from arcushub.cli import cli
from arcushub.debug_keys import extract_debug_key

DATA_DIR = Path(__file__).resolve().parent.parent / "hub"


def test_extract(tmp_path):
    out = extract_debug_key("lwh-9589", DATA_DIR, tmp_path)
    assert out == tmp_path / "LWH-9589.dbg"
    assert out.stat().st_size == 512


def test_missing_archive_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        extract_debug_key("LWA-1234", DATA_DIR, tmp_path)


@pytest.mark.parametrize("hub_id,message", [
    ("LW-1234", "Invalid hub ID format"),
    ("ZZZ-1234", "Unknown hub prefix"),
    ("LWA-1234", "Debug key archive not found"),
])
def test_cli_errors_are_clean(tmp_path, hub_id, message):
    result = CliRunner().invoke(cli, ["debug-key", hub_id, "--data-dir", str(DATA_DIR), "-o", str(tmp_path / "k.dbg")])
    assert result.exit_code == 1
    assert message in result.output
    assert "Traceback" not in result.output


def test_cli_output_to_new_directory(tmp_path):
    dest = tmp_path / "new" / "dir" / "key.dbg"
    result = CliRunner().invoke(cli, ["debug-key", "LWH-9589", "--data-dir", str(DATA_DIR), "-o", str(dest)])
    assert result.exit_code == 0, result.output
    assert dest.stat().st_size == 512

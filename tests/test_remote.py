import io
import os

import click
import pytest
from click.testing import CliRunner
from conftest import FakeClient

from arcushub.cli import _download, _pump, _run, _upload, cli


def test_run_returns_stdout():
    assert _run(FakeClient(), "echo hello").strip() == "hello"


def test_run_failure_includes_stderr():
    with pytest.raises(click.ClickException, match="boom"):
        _run(FakeClient(), "echo boom >&2; exit 2")


def test_run_unchecked_ignores_failure():
    assert _run(FakeClient(), "echo partial; exit 1", check=False).strip() == "partial"


def test_upload_success(tmp_path):
    data = os.urandom(200_000)
    dest = tmp_path / "with space.bin"
    _upload(FakeClient(), io.BytesIO(data), len(data), str(dest), "up")
    assert dest.read_bytes() == data


def test_upload_truncated_is_detected_and_removed(tmp_path):
    data = os.urandom(200_000)
    dest = tmp_path / "short.bin"
    with pytest.raises(click.ClickException, match="incomplete: 1000 of 200000"):
        _upload(FakeClient(truncate_after=1000), io.BytesIO(data), len(data), str(dest), "up")
    assert not dest.exists()


def test_upload_write_error(tmp_path):
    with pytest.raises(click.ClickException, match="failed"):
        _upload(FakeClient(), io.BytesIO(b"abc"), 3, str(tmp_path / "missing" / "x"), "up")


def test_download_failure_removes_local_file(tmp_path):
    local = tmp_path / "out.log"
    with pytest.raises(click.ClickException, match="Failed to read"):
        _download(FakeClient(), str(tmp_path / "nope"), local, "down")
    assert not local.exists()


def test_ssh_command_passes_output_and_exit_code(fake_hub):
    result = CliRunner().invoke(cli, ["ssh", "hub", "echo out; echo err >&2; exit 3"])
    assert result.exit_code == 3
    assert "out" in result.output and "err" in result.output
    assert fake_hub.closed


def test_ssh_command_large_stderr_not_truncated(fake_hub):
    cmd = "i=0; while [ $i -lt 2000 ]; do echo line$i >&2; i=$((i+1)); done"
    result = CliRunner().invoke(cli, ["ssh", "hub", cmd])
    assert result.exit_code == 0
    assert "line1999" in result.output


def test_scp_round_trip(fake_hub, tmp_path):
    remote_dir = tmp_path / "remote dir"
    remote_dir.mkdir()
    src = tmp_path / "local.bin"
    src.write_bytes(os.urandom(100_000))

    up = CliRunner().invoke(cli, ["scp", str(src), f"hub:{remote_dir}/"])
    assert up.exit_code == 0, up.output
    assert (remote_dir / "local.bin").read_bytes() == src.read_bytes()

    back = tmp_path / "back.bin"
    down = CliRunner().invoke(cli, ["scp", f"hub:{remote_dir}/local.bin", str(back)])
    assert down.exit_code == 0, down.output
    assert back.read_bytes() == src.read_bytes()


def test_scp_missing_remote_dir(fake_hub, tmp_path):
    src = tmp_path / "f"
    src.write_text("x")
    result = CliRunner().invoke(cli, ["scp", str(src), f"hub:{tmp_path}/nope/f"])
    assert result.exit_code == 1
    assert "Remote directory does not exist" in result.output


def test_pump_returns_when_channel_closes_without_exit_status():
    class DroppedChannel:
        closed = True

        def fileno(self):
            r, w = os.pipe()
            os.write(w, b"x")
            return r

        def recv_ready(self):
            return False

        def recv_stderr_ready(self):
            return False

        def exit_status_ready(self):
            return False

    assert _pump(DroppedChannel(), io.BytesIO(), io.BytesIO()) == -1

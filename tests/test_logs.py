import pytest
from conftest import separate_streams_runner

from arcushub import cli as cli_mod
from arcushub.cli import cli

# Logs aren't always valid UTF-8, and stdout has to pass them through untouched
CURRENT = b"current run \xff\n"
PREVIOUS = b"previous run\n"


@pytest.fixture
def workdir(fake_hub, tmp_path, monkeypatch):
    """Point the log paths at files the fake hub can read, and run in an empty directory."""
    hub = tmp_path / "hub"
    hub.mkdir()
    (hub / "hubAgent.log").write_bytes(CURRENT)
    (hub / "hubAgent.last").write_bytes(PREVIOUS)
    monkeypatch.setattr(cli_mod, "_AGENT_LOG", str(hub / "hubAgent.log"))
    monkeypatch.setattr(cli_mod, "_AGENT_LAST_LOG", str(hub / "hubAgent.last"))
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return work


@pytest.mark.parametrize("args, name, content", [
    ([], "hubAgent.log", CURRENT),
    (["--previous"], "hubAgent.last", PREVIOUS),
])
def test_logs_downloads_into_the_current_directory(workdir, args, name, content):
    result = separate_streams_runner().invoke(cli, ["logs", "hub", *args])
    assert result.exit_code == 0, result.output
    assert [p.name for p in workdir.iterdir()] == [name]
    assert (workdir / name).read_bytes() == content
    assert result.stdout == ""


@pytest.mark.parametrize("args, content", [([], CURRENT), (["--previous"], PREVIOUS)])
def test_logs_to_stdout(workdir, args, content):
    result = separate_streams_runner().invoke(cli, ["logs", "hub", "-o", "-", *args])
    assert result.exit_code == 0, result.output
    assert result.stdout_bytes == content
    assert list(workdir.iterdir()) == []


def test_logs_to_stdout_reports_a_missing_log(workdir, monkeypatch):
    # hubAgent.last is missing until the agent first restarts after boot
    monkeypatch.setattr(cli_mod, "_AGENT_LAST_LOG", str(workdir / "hubAgent.last"))
    result = separate_streams_runner().invoke(cli, ["logs", "hub", "-o", "-", "--previous"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Failed to read" in result.stderr


def test_logs_previous_cannot_be_followed(workdir):
    result = separate_streams_runner().invoke(cli, ["logs", "hub", "--previous", "-f"])
    assert result.exit_code == 2
    assert "--previous can't be followed" in result.stderr


def test_a_failed_download_keeps_the_earlier_copy(workdir, monkeypatch):
    # Opening the file first used to empty a log saved by an earlier run, then delete it
    (workdir / "hubAgent.last").write_bytes(b"saved crash log\n")
    monkeypatch.setattr(cli_mod, "_AGENT_LAST_LOG", str(workdir / "missing"))
    result = separate_streams_runner().invoke(cli, ["logs", "hub", "--previous"])
    assert result.exit_code == 1
    assert "Failed to read" in result.stderr
    assert [p.name for p in workdir.iterdir()] == ["hubAgent.last"]
    assert (workdir / "hubAgent.last").read_bytes() == b"saved crash log\n"


def test_a_path_to_a_file_named_dash_is_not_stdout(workdir):
    result = separate_streams_runner().invoke(cli, ["logs", "hub", "-o", "./-"])
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert (workdir / "-").read_bytes() == CURRENT


def test_logs_refuses_a_directory_as_output(workdir):
    result = separate_streams_runner().invoke(cli, ["logs", "hub", "-o", str(workdir)])
    assert result.exit_code == 2
    assert "is a directory" in result.stderr


def test_logs_reports_a_missing_local_directory(workdir):
    result = separate_streams_runner().invoke(cli, ["logs", "hub", "-o", "nope/hub.log"])
    assert result.exit_code == 1
    assert "Can't write nope/hub.log" in result.stderr
    assert list(workdir.iterdir()) == []

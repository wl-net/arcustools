import os
import subprocess

import pytest

from arcushub import cli as cli_mod


class FakeChannel:
    """Stand-in for a paramiko Channel that runs the command in a local `sh -c`."""

    def __init__(self, truncate_after=None):
        self._truncate_after = truncate_after
        self._done = False
        self._sent = 0
        # Always-readable fd so select() in _pump returns immediately
        r, w = os.pipe()
        os.write(w, b"x")
        self._fd = r

    def fileno(self):
        return self._fd

    def exec_command(self, cmd):
        self._proc = subprocess.Popen(["sh", "-c", cmd], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def sendall(self, data):
        if self._truncate_after is not None:
            data = data[:max(0, self._truncate_after - self._sent)]
        self._sent += len(data)
        self._proc.stdin.write(data)

    def shutdown_write(self):
        self._close_stdin()

    def _close_stdin(self):
        try:
            self._proc.stdin.close()
        except BrokenPipeError:
            pass

    def _finish(self):
        if not self._done:
            self._close_stdin()
            self._out, self._err = self._proc.communicate()
            self._status = self._proc.returncode
            self._done = True

    def recv_ready(self):
        self._finish()
        return bool(self._out)

    def recv(self, n):
        self._finish()
        data, self._out = self._out[:n], self._out[n:]
        return data

    def recv_stderr_ready(self):
        self._finish()
        return bool(self._err)

    def recv_stderr(self, n):
        self._finish()
        data, self._err = self._err[:n], self._err[n:]
        return data

    def exit_status_ready(self):
        self._finish()
        return True

    def recv_exit_status(self):
        self._finish()
        return self._status


class FakeClient:
    """Stand-in for a paramiko SSHClient. truncate_after limits bytes accepted by the first channel."""

    def __init__(self, truncate_after=None):
        self._truncate_after = truncate_after
        self.closed = False

    def get_transport(self):
        return self

    def open_session(self):
        chan = FakeChannel(self._truncate_after)
        self._truncate_after = None
        return chan

    def close(self):
        self.closed = True


@pytest.fixture
def fake_hub(monkeypatch):
    """Route CLI commands to a FakeClient instead of a real hub."""
    client = FakeClient()
    monkeypatch.setattr(cli_mod, "_resolve_host", lambda host, timeout=5.0: host)
    monkeypatch.setattr(cli_mod, "_connect", lambda *a, **kw: client)
    return client

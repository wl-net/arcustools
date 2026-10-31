import paramiko
import pytest

from arcushub.ssh import ROOT_PASSWORDS, connect


@pytest.fixture
def logins(monkeypatch):
    """Record the options of each paramiko login. Only the last known password is accepted."""
    seen = []

    def fake_connect(self, host, **kwargs):
        seen.append(kwargs)
        if kwargs.get("password") != ROOT_PASSWORDS[-1]:
            raise paramiko.AuthenticationException("rejected")

    monkeypatch.setattr(paramiko.SSHClient, "connect", fake_connect)
    return seen


def test_connect_never_uses_the_ssh_agent(logins):
    connect("10.0.0.1")
    assert len(logins) == 1 + len(ROOT_PASSWORDS)
    assert not any(login["allow_agent"] for login in logins)


def test_connect_tries_key_files_before_passwords(logins):
    connect("10.0.0.1")
    assert logins[0]["look_for_keys"] is True
    assert "password" not in logins[0]

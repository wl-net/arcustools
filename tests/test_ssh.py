import paramiko
import pytest

from arcushub import ssh
from arcushub.ssh import ROOT_PASSWORDS, connect, key_login_works, remember_key


@pytest.fixture(autouse=True)
def key_list(monkeypatch, tmp_path):
    monkeypatch.setattr(ssh, "_KEYS_PATH", tmp_path / "ssh_keys.json")


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


def test_failed_logins_leave_no_connection_open(monkeypatch):
    # Connecting a client again would drop its transport still open, one per
    # attempt, and dropbear refuses a sixth unauthenticated connection from an IP
    clients, closed = [], []

    def fake_connect(self, host, **kwargs):
        clients.append(self)
        if kwargs.get("password") != ROOT_PASSWORDS[-1]:
            raise paramiko.AuthenticationException("rejected")

    monkeypatch.setattr(paramiko.SSHClient, "connect", fake_connect)
    monkeypatch.setattr(paramiko.SSHClient, "close", lambda self: closed.append(self))

    winner = connect("10.0.0.1")
    assert len(set(map(id, clients))) == 1 + len(ROOT_PASSWORDS)
    assert winner is clients[-1]
    assert [id(c) for c in closed] == [id(c) for c in clients[:-1]]


def test_key_chosen_for_setup_is_offered_on_later_logins(logins, tmp_path):
    key = tmp_path / "hub_ed25519"
    key.write_text("private")
    remember_key(key)
    remember_key(key)

    connect("10.0.0.1")
    assert logins[0]["key_filename"] == [str(key)]


def test_key_that_has_since_gone_is_not_offered(logins, tmp_path):
    key = tmp_path / "hub_ed25519"
    key.write_text("private")
    remember_key(key)
    key.unlink()

    connect("10.0.0.1")
    assert logins[0]["key_filename"] is None


def test_unreadable_key_list_means_no_extra_keys(logins):
    ssh._KEYS_PATH.write_text("not json")

    connect("10.0.0.1")
    assert logins[0]["key_filename"] is None


def test_key_login_check_uses_that_key_alone(monkeypatch, tmp_path):
    seen, closed = {}, []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda self, host, **kwargs: seen.update(kwargs))
    monkeypatch.setattr(paramiko.SSHClient, "close", lambda self: closed.append(self))

    assert key_login_works("10.0.0.1", 22, "root", tmp_path / "key") is True
    assert seen["key_filename"] == str(tmp_path / "key")
    assert seen["look_for_keys"] is False and seen["allow_agent"] is False
    assert len(closed) == 1


@pytest.mark.parametrize("error", [
    paramiko.AuthenticationException("rejected"),
    paramiko.PasswordRequiredException("encrypted key"),
    OSError("connection refused"),
])
def test_key_login_check_says_no_when_the_key_cannot_log_in(monkeypatch, tmp_path, error):
    def fail(self, host, **kwargs):
        raise error

    monkeypatch.setattr(paramiko.SSHClient, "connect", fail)
    assert key_login_works("10.0.0.1", 22, "root", tmp_path / "key") is False


def test_connect_never_uses_the_ssh_agent(logins):
    connect("10.0.0.1")
    assert len(logins) == 1 + len(ROOT_PASSWORDS)
    assert not any(login["allow_agent"] for login in logins)


def test_connect_tries_key_files_before_passwords(logins):
    connect("10.0.0.1")
    assert logins[0]["look_for_keys"] is True
    assert "password" not in logins[0]

from __future__ import annotations

import fcntl
import json
import os
import select
import struct
import sys
import termios
import tty
from pathlib import Path

import paramiko

ROOT_PASSWORDS = [
    r"3XSgE27w5VJ3qvxK33dn",  # source builds
    r"zm{[*f6gB5X($]R9",   # hubOS 3.x releases
    r"kz58!~Eb.RZ?+bqb",   # hubOS 2.x releases
]


_KEYS_PATH = Path.home() / ".cache" / "arcushub" / "ssh_keys.json"


def _installed_keys() -> list[str]:
    """Key files setup-ssh-key was pointed at, which look_for_keys wouldn't find by name."""
    try:
        keys = json.loads(_KEYS_PATH.read_text())
    except (OSError, ValueError):
        return []
    return [key for key in keys if Path(key).exists()]


def remember_key(key_file: Path) -> None:
    """Offer this private key on every login from now on."""
    keys = _installed_keys()
    if str(key_file) not in keys:
        _KEYS_PATH.parent.mkdir(parents=True, exist_ok=True)
        _KEYS_PATH.write_text(json.dumps(keys + [str(key_file)]))


def _login(host: str, port: int, user: str, **auth) -> paramiko.SSHClient:
    """Make one login attempt on a client of its own.

    Connecting a client again drops its old transport without closing it, which
    would leave each failed attempt open until we exit. Hubs run dropbear, which
    by default refuses a sixth unauthenticated connection from one IP.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, allow_agent=False, **auth)
    except Exception:
        client.close()
        raise
    return client


def connect(host: str, port: int = 22, user: str = "root", password: str | None = None) -> paramiko.SSHClient:
    """Connect to a hub via SSH.

    With an explicit password, use only that. Otherwise try local SSH keys
    (installed by `arcushub setup-ssh-key`) first, then the known passwords.

    The SSH agent is left out. paramiko signs with each agent key without first
    asking the server whether it would accept it, so a Touch ID protected key
    in the agent would prompt on every connection, for a key hubs don't have.
    """
    last_err = None
    if not password:
        try:
            return _login(host, port, user, key_filename=_installed_keys() or None, look_for_keys=True)
        except paramiko.SSHException as e:
            # AuthenticationException, or "No authentication methods available" with no keys
            last_err = e

    passwords = [password] if password else ROOT_PASSWORDS
    for pw in passwords:
        try:
            return _login(
                host, port, user, password=pw, look_for_keys=False,
                disabled_algorithms={"keys": [], "pubkeys": []},
            )
        except paramiko.AuthenticationException as e:
            last_err = e

    raise paramiko.AuthenticationException(f"All passwords failed for {user}@{host}:{port}") from last_err


def key_login_works(host: str, port: int, user: str, key_file: Path) -> bool:
    """Try a login with this key file alone."""
    try:
        client = _login(host, port, user, key_filename=str(key_file), look_for_keys=False)
    except (paramiko.SSHException, OSError):
        return False
    client.close()
    return True


def interactive_shell(client: paramiko.SSHClient) -> None:
    """Drop into an interactive SSH shell session."""
    # Get terminal size so the remote PTY matches
    try:
        packed = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, b"\x00" * 8)
        rows, cols = struct.unpack("HHHH", packed)[:2]
    except OSError:
        rows, cols = 24, 80

    chan = client.invoke_shell(width=cols, height=rows)
    oldtty = termios.tcgetattr(sys.stdin)
    try:
        # Flush any buffered stdin (e.g. the Enter that launched the command)
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        chan.settimeout(0.0)

        after_newline = True  # start of session counts as after newline
        escape_seen = False

        while True:
            r, _w, _e = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    data = chan.recv(1024)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except EOFError:
                    break
            if sys.stdin in r:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                # Process escape sequences byte-by-byte (like OpenSSH ~.)
                out = bytearray()
                for byte in data:
                    if escape_seen:
                        escape_seen = False
                        if byte == ord("."):
                            sys.stdout.buffer.write(b"\r\nConnection closed.\r\n")
                            sys.stdout.buffer.flush()
                            return
                        elif byte == ord("~"):
                            # ~~ sends a literal ~
                            out.append(byte)
                            after_newline = False
                            continue
                        else:
                            # Not a recognized escape; send the ~ we swallowed
                            out.append(ord("~"))
                            out.append(byte)
                            after_newline = (byte in (0x0a, 0x0d))
                            continue
                    if after_newline and byte == ord("~"):
                        escape_seen = True
                        continue
                    after_newline = (byte in (0x0a, 0x0d))
                    out.append(byte)
                if out:
                    chan.send(bytes(out))
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
        chan.close()

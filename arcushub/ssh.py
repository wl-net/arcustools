import fcntl
import os
import select
import struct
import sys
import termios
import tty

import paramiko

ROOT_PASSWORDS = [
    r"zm{[*f6gB5X($]R9",   # hubOS 3.x releases
    r"kz58!~Eb.RZ?+bqb",   # hubOS 2.x releases
    r"3XSgE27w5VJ3qvxK33dn",  # source builds
]


def connect(host: str, port: int = 22, user: str = "root", password: str | None = None) -> paramiko.SSHClient:
    """Connect to a hub via SSH, trying known passwords if none is provided."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    passwords = [password] if password else ROOT_PASSWORDS
    last_err = None
    for pw in passwords:
        try:
            client.connect(
                host, port=port, username=user, password=pw,
                look_for_keys=False, allow_agent=False,
                disabled_algorithms={"keys": [], "pubkeys": []},
            )
            return client
        except paramiko.AuthenticationException as e:
            last_err = e
            continue

    raise paramiko.AuthenticationException(f"All passwords failed for {user}@{host}:{port}") from last_err


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
                chan.send(data)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
        chan.close()

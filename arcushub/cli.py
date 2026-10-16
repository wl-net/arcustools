from __future__ import annotations

import hashlib
import io
import json
import re
import select
import shlex
import socket
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import click

_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class _Progress:
    """Thread-safe byte counter for transfer progress."""
    def __init__(self, total: int | None = None):
        self.transferred = 0
        self.total = total
        self._lock = threading.Lock()

    def update(self, n: int):
        with self._lock:
            self.transferred += n

    def status(self) -> str:
        with self._lock:
            if self.total:
                pct = self.transferred / self.total * 100
                return f"{_format_size(self.transferred)}/{_format_size(self.total)} ({pct:.0f}%)"
            return _format_size(self.transferred)


class _CountingWriter:
    """File wrapper that reports bytes written to a _Progress."""
    def __init__(self, f, progress: _Progress):
        self._f = f
        self._progress = progress

    def write(self, data: bytes):
        self._f.write(data)
        self._progress.update(len(data))

    def flush(self):
        self._f.flush()


@contextmanager
def _spinner(message: str, progress: _Progress | None = None):
    """Show a braille spinner with a message while work runs in the block."""
    stop = threading.Event()
    failed = threading.Event()

    def spin():
        i = 0
        while not stop.is_set():
            frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
            suffix = f"  {progress.status()}" if progress else ""
            click.echo(f"\r\033[K{frame} {message}{suffix}", nl=False)
            i += 1
            stop.wait(0.08)
        suffix = f"  {progress.status()}" if progress else ""
        mark = "✘" if failed.is_set() else "✔"
        click.echo(f"\r\033[K{mark} {message}{suffix}")

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        yield
    except BaseException:
        failed.set()
        raise
    finally:
        stop.set()
        t.join()

# Default data directory: the hub/ dir in the repo root (sibling of arcushub/)
_PACKAGE_DIR = Path(__file__).resolve().parent
_DEFAULT_DATA_DIR = _PACKAGE_DIR.parent / "hub"


@click.group()
def cli():
    """Arcus hub management tools."""


_CACHE_PATH = Path.home() / ".cache" / "arcushub" / "hosts.json"


def _is_hub_id(value: str) -> bool:
    """Check if a string looks like a hub ID (e.g. LWR-2389)."""
    return bool(re.match(r"^[A-Za-z]{3}-\d{4}$", value))


def _load_cache() -> dict:
    if _CACHE_PATH.exists():
        try:
            return json.loads(_CACHE_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_cache(cache: dict) -> None:
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CACHE_PATH.write_text(json.dumps(cache))


def _is_reachable(ip: str, port: int = 22, timeout: float = 1.0) -> bool:
    """Quick TCP connect check."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


_ATF_COM = 0x2  # /proc/net/arp flag: entry is complete (resolved)


def _normalize_mac(mac: str) -> str:
    return ":".join(f"{int(b, 16):02x}" for b in mac.split(":"))


def _parse_proc_arp(text: str) -> list[tuple[str, str]]:
    """Parse /proc/net/arp contents into [(ip, mac), ...], keeping only complete entries."""
    entries = []
    for line in text.splitlines()[1:]:  # skip header
        fields = line.split()
        if len(fields) < 4:
            continue
        # Skip incomplete/failed entries: the kernel keeps the last
        # MAC around after the host stops answering at this IP.
        if not int(fields[2], 16) & _ATF_COM:
            continue
        entries.append((fields[0], _normalize_mac(fields[3])))
    return entries


def _parse_arp_a(text: str) -> list[tuple[str, str]]:
    """Parse `arp -a` output (macOS, BSDs) into [(ip, mac), ...]."""
    entries = []
    for line in text.splitlines():
        mac_match = re.search(r"at\s+([0-9a-f:]+)", line.lower())
        ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
        if mac_match and ip_match:
            entries.append((ip_match.group(1), _normalize_mac(mac_match.group(1))))
    return entries


def _read_arp() -> list[tuple[str, str]]:
    """Return resolved (ip, mac) pairs from the system ARP table."""
    try:
        with open("/proc/net/arp") as f:
            return _parse_proc_arp(f.read())
    except OSError:
        pass
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return []
    return _parse_arp_a(result.stdout)


def _find_all_hubs_in_arp() -> list[tuple[str, str]]:
    """Scan ARP table for all MACs matching known Arcus OUIs. Returns [(ip, mac), ...]."""
    from .hubid import KNOWN_OUIS

    oui_prefixes = {f"{(oui >> 16) & 0xFF:02x}:{(oui >> 8) & 0xFF:02x}:{oui & 0xFF:02x}" for oui in KNOWN_OUIS}
    return [(ip, mac) for ip, mac in _read_arp() if mac[:8] in oui_prefixes]


def _find_in_arp(mac_even: str, mac_odd: str) -> str | None:
    """Search the ARP table for a MAC, return the IP or None."""
    for ip, mac in _read_arp():
        if mac in (mac_even, mac_odd):
            return ip
    return None


def _connect(host: str, port: int = 22, user: str = "root", password: str | None = None):
    """Connect to a hub via SSH, showing a spinner during the handshake."""
    from .ssh import connect

    with _spinner(f"Connecting to {user}@{host}:{port}"):
        client = connect(host, port=port, user=user, password=password)
    return client


def _hub_options(f):
    """Add the --port/--user/--password options shared by every command that connects to a hub."""
    f = click.option("--password", default=None, help="Override password (skip auto-detection).")(f)
    f = click.option("--user", default="root", help="SSH username.")(f)
    f = click.option("--port", default=22, help="SSH port.")(f)
    return f


@contextmanager
def _hub_session(host: str, port: int, user: str, password: str | None):
    """Resolve host (IP, hostname, or hub ID), connect, and yield the SSH client."""
    ip = _resolve_host(host)
    try:
        client = _connect(ip, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e)) from e
    try:
        yield client
    finally:
        client.close()


def _pump(chan, out, err) -> int:
    """Copy a channel's stdout/stderr into out/err as data arrives; return the exit status.

    Draining both streams together keeps a chatty stderr from filling its
    window and stalling the remote command. Returns -1 if the connection
    closed without an exit status (e.g. the hub rebooted).
    """
    while True:
        select.select([chan], [], [], 0.1)
        while chan.recv_ready():
            out.write(chan.recv(65536))
            out.flush()
        while chan.recv_stderr_ready():
            err.write(chan.recv_stderr(65536))
            err.flush()
        # exit-status arrives after all data, so once it's here the buffers are complete
        if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
            return chan.recv_exit_status()


def _run(client, cmd: str, check: bool = True) -> str:
    """Run cmd on the hub and return its stdout. Raises ClickException on failure if check."""
    chan = client.get_transport().open_session()
    chan.exec_command(cmd)
    out, err = io.BytesIO(), io.BytesIO()
    status = _pump(chan, out, err)
    if check and status != 0:
        msg = err.getvalue().decode(errors="replace").strip() or f"exit code {status}"
        raise click.ClickException(f"`{cmd}` failed: {msg}")
    return out.getvalue().decode(errors="replace")


def _upload(client, fileobj, size: int, remote_path: str, label: str) -> None:
    """Stream fileobj to remote_path via `cat` (hub SSH lacks SFTP) and verify it arrived intact.

    Raises ClickException and removes the partial remote file if the write fails
    or the remote size doesn't match.
    """
    quoted = shlex.quote(remote_path)
    prog = _Progress(total=size)
    try:
        with _spinner(label, progress=prog):
            chan = client.get_transport().open_session()
            chan.exec_command(f"cat > {quoted}")
            try:
                while True:
                    chunk = fileobj.read(65536)
                    if not chunk:
                        break
                    chan.sendall(chunk)
                    prog.update(len(chunk))
                chan.shutdown_write()
            except (OSError, EOFError):
                pass  # remote cat died early; exit status below explains why
            status = chan.recv_exit_status()
            if status != 0:
                err = chan.recv_stderr(4096).decode(errors="replace").strip()
                raise click.ClickException(f"Upload to {remote_path} failed: {err or f'exit code {status}'}")

            remote_size = _run(client, f"wc -c < {quoted}", check=False).strip()
            if remote_size != str(size):
                raise click.ClickException(
                    f"Upload to {remote_path} incomplete: {remote_size or '?'} of {size} bytes written"
                )
    except click.ClickException:
        _run(client, f"rm -f {quoted}", check=False)
        raise


def _download(client, remote_path: str, local_path: Path, label: str) -> None:
    """Stream remote_path into local_path. Removes the local file and raises ClickException on failure."""
    prog = _Progress()
    err = io.BytesIO()
    try:
        with _spinner(label, progress=prog), open(local_path, "wb") as f:
            chan = client.get_transport().open_session()
            chan.exec_command(f"cat {shlex.quote(remote_path)}")
            status = _pump(chan, _CountingWriter(f, prog), err)
            if status != 0:
                msg = err.getvalue().decode(errors="replace").strip() or f"exit code {status}"
                raise click.ClickException(f"Failed to read {remote_path}: {msg}")
    except click.ClickException:
        Path(local_path).unlink(missing_ok=True)
        raise


def _resolve_host(host: str, timeout: float = 5.0) -> str:
    """If host is a hub ID, find its IP on the network. Otherwise return as-is.

    Resolution order:
    1. Check local cache (~/.cache/arcushub/hosts.json) + quick TCP probe
    2. Check ARP table (instant, no network traffic)
    3. SSDP discovery (slow, populates ARP table) + check ARP again
    """
    if not _is_hub_id(host):
        return host

    from .hubid import hub_id_to_mac
    from .ssdp import discover

    hub_id = host.upper()
    try:
        mac = hub_id_to_mac(hub_id)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    mac_bytes = bytes(int(b, 16) for b in mac.split(":"))
    mac_even = ":".join(f"{b:02x}" for b in mac_bytes)
    mac_odd = ":".join(f"{b:02x}" for b in mac_bytes[:-1]) + f":{mac_bytes[-1] | 1:02x}"

    # 1. Check cache. The probe refreshes the ARP entry, so confirm the MAC
    # at that IP is still this hub; DHCP may have handed it to another hub.
    cache = _load_cache()
    cached_ip = cache.get(hub_id)
    if cached_ip and _is_reachable(cached_ip) and _find_in_arp(mac_even, mac_odd) == cached_ip:
        return cached_ip

    click.echo(f"Resolving {hub_id} (MAC {mac_even} or {mac_odd})...")

    # 2. Check ARP table (already populated from recent traffic)
    ip = _find_in_arp(mac_even, mac_odd)
    if ip:
        cache[hub_id] = ip
        _save_cache(cache)
        return ip

    # 3. SSDP discovery to populate ARP table, then check again
    with _spinner("Running SSDP discovery"):
        discover(timeout=timeout)

    ip = _find_in_arp(mac_even, mac_odd)
    if ip:
        cache[hub_id] = ip
        _save_cache(cache)
        return ip

    raise click.ClickException(f"Hub {hub_id} not found on the network.")


@cli.command("ssh")
@click.argument("host")
@click.argument("command", nargs=-1)
@_hub_options
def ssh(host, command, port, user, password):
    """SSH into an Arcus hub. HOST can be an IP address, hostname, or hub ID.

    If COMMAND is given, run it on the hub and exit. Otherwise open an interactive shell.
    Like ssh(1), COMMAND is joined with spaces and run by the hub's shell, so pipes work.

    \b
    Examples:
      arcushub ssh LWR-2389
      arcushub ssh LWR-2389 killall java
      arcushub ssh 10.0.1.5 cat /tmp/hubAgent.log
      arcushub ssh LWR-2389 'ps | grep java'
    """
    from .ssh import interactive_shell

    with _hub_session(host, port, user, password) as client:
        if command:
            chan = client.get_transport().open_session()
            chan.exec_command(" ".join(command))
            status = _pump(chan, sys.stdout.buffer, sys.stderr.buffer)
        else:
            interactive_shell(client)
            status = 0
    sys.exit(status)


@cli.command("debug-key")
@click.argument("hub_id")
@click.option("--data-dir", type=click.Path(exists=True, path_type=Path), default=_DEFAULT_DATA_DIR,
              help="Path to hub data directory.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Output file path (default: ./<HUB_ID>.dbg).")
def debug_key(hub_id, data_dir, output):
    """Extract the debug key file for a hub."""
    from .debug_keys import extract_debug_key

    output_dir = output.parent if output else Path.cwd()
    if output:
        # If user gave a full output path, we extract to its parent and rename
        output.parent.mkdir(parents=True, exist_ok=True)
    try:
        out = extract_debug_key(hub_id, data_dir, output_dir)
    except (ValueError, FileNotFoundError) as e:
        raise click.ClickException(str(e)) from e
    except KeyError as e:
        raise click.ClickException(e.args[0]) from e
    if output and out.name != output.name:
        out.rename(output)
        out = output

    click.echo(out)


@cli.command("enable-dropbear")
@click.argument("host")
@_hub_options
def enable_dropbear(host, port, user, password):
    """Enable dropbear SSH server on a hub by default. HOST can be an IP, hostname, or hub ID."""
    with _hub_session(host, port, user, password) as client:
        _run(client, "touch /data/config/enable_console")
        click.echo("Dropbear enabled. It will start on next boot.")


@cli.command("setup-ssh-key")
@click.argument("host")
@_hub_options
@click.option("--key", type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to SSH public key file (default: auto-detect).")
def setup_ssh_key(host, port, user, password, key):
    """Push an SSH public key to a hub for passwordless login. HOST can be an IP, hostname, or hub ID."""
    if key is None:
        ssh_dir = Path.home() / ".ssh"
        for name in ("id_ed25519.pub", "id_rsa.pub"):
            candidate = ssh_dir / name
            if candidate.exists():
                key = candidate
                break
        if key is None:
            raise click.ClickException(
                "No SSH public key found. Generate one with ssh-keygen or specify --key."
            )

    key_content = key.read_text().strip()
    click.echo(f"Using key: {key}")

    with _hub_session(host, port, user, password) as client:
        auth_keys = "/data/config/dropbear/authorized_keys"
        quoted_key = shlex.quote(key_content)
        # Print a marker only when appending, so re-running doesn't duplicate the key
        cmd = (
            f"mkdir -p /data/config/dropbear && touch {auth_keys} && "
            f"(grep -qxF {quoted_key} {auth_keys} || (echo {quoted_key} >> {auth_keys} && echo added))"
        )
        if _run(client, cmd).strip() == "added":
            click.echo("SSH key installed. You can now connect without a password.")
        else:
            click.echo("SSH key already installed.")


@cli.command()
@click.argument("hub_id")
@click.option("--timeout", "-t", default=5.0, help="SSDP discovery timeout in seconds.")
def find(hub_id, timeout):
    """Find a hub's IP address on the local network by its hub ID."""
    ip = _resolve_host(hub_id, timeout=timeout)
    click.echo(ip)


@cli.command()
@click.option("--timeout", "-t", default=5.0, help="SSDP discovery timeout in seconds.")
def hubs(timeout):
    """Discover all Arcus hubs on the local network."""
    from .hubid import mac_to_hub_id
    from .ssdp import discover

    with _spinner("Running SSDP discovery"):
        discover(timeout=timeout)

    found = _find_all_hubs_in_arp()
    if not found:
        click.echo("No hubs found.")
        return

    cache = _load_cache()
    rows = []
    with _spinner(f"Pinging {len(found)} hub{'s' if len(found) != 1 else ''}"):
        for ip, mac in found:
            hub_id = mac_to_hub_id(mac)
            cache[hub_id] = ip
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", ip],
                    capture_output=True, timeout=3, check=False,
                )
                reachable = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                reachable = False
            rows.append((hub_id, ip, mac, reachable))
    _save_cache(cache)

    # Print table
    id_w = max(len(r[0]) for r in rows)
    ip_w = max(len(r[1]) for r in rows)
    click.echo(f"{'HUB_ID':<{id_w}}  {'IP':<{ip_w}}  MAC")
    for hub_id, ip, mac, reachable in rows:
        note = "" if reachable else "  (unreachable)"
        click.echo(f"{hub_id:<{id_w}}  {ip:<{ip_w}}  {mac}{note}")


@cli.command()
@click.argument("host")
@_hub_options
def ping(host, port, user, password):
    """Ping a hub and show basic status. HOST can be an IP, hostname, or hub ID."""
    host = _resolve_host(host)

    # ICMP ping
    click.echo(f"Pinging {host}...")
    try:
        result = subprocess.run(
            ["ping", "-c", "3", host],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0:
            # Extract summary line (e.g. "rtt min/avg/max/mdev = ...")
            for line in result.stdout.splitlines():
                if "min/avg/max" in line or "round-trip" in line:
                    click.echo(f"  Latency: {line.strip()}")
                    break
            else:
                click.echo("  Ping: OK")
        else:
            click.echo("  Ping: FAILED (no response)")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        click.echo("  Ping: FAILED (timeout or ping not available)")

    # SSH port check
    ssh_up = _is_reachable(host, port=port)
    click.echo(f"  SSH (port {port}): {'UP' if ssh_up else 'DOWN'}")

    if not ssh_up:
        return

    # Grab uptime and agent status via SSH; a login failure is reported, not fatal
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        click.echo(f"  SSH login failed: {e}")
        return

    try:
        uptime = _run(client, "uptime", check=False).strip()
        if uptime:
            click.echo(f"  Uptime: {uptime}")

        # The agent is the hub's only JVM (agent_stop just does `killall java`)
        agent_pid = _run(client, "pidof java", check=False).strip()
        click.echo(f"  Hub agent: {'running (pid ' + agent_pid.split()[0] + ')' if agent_pid else 'not running'}")
    finally:
        client.close()


@cli.command()
@click.argument("host")
@_hub_options
def reboot(host, port, user, password):
    """Reboot a hub. HOST can be an IP address, hostname, or hub ID."""
    with _hub_session(host, port, user, password) as client:
        client.exec_command("/sbin/reboot")
        click.echo(f"Reboot command sent to {host}.")


@cli.group()
def agent():
    """Hub agent management commands."""


@agent.command()
@click.argument("host")
@_hub_options
def restart(host, port, user, password):
    """Restart the hub agent. HOST can be an IP address, hostname, or hub ID."""
    with _hub_session(host, port, user, password) as client:
        with _spinner("Restarting agent"):
            _run(client, "/home/root/bin/agent_stop && /home/root/bin/agent_start")
        click.echo(f"Agent restarted on {host}.")


@agent.command()
@click.argument("host")
@_hub_options
def reinstall(host, port, user, password):
    """Reinstall the hub agent. Deletes /data/agent and reboots to re-extract from tarball.

    Preserves pairing data in /data/iris. HOST can be an IP, hostname, or hub ID.
    """
    with _hub_session(host, port, user, password) as client:
        click.echo("Removing /data/agent and rebooting...")
        client.exec_command("rm -rf /data/agent && /sbin/reboot")
        click.echo(f"Agent reinstall initiated on {host}.")


@agent.command()
@click.argument("host")
@_hub_options
def reset(host, port, user, password):
    """Factory reset the hub agent. Deletes /data/agent AND /data/iris, then reboots.

    WARNING: This wipes all pairing data. HOST can be an IP, hostname, or hub ID.
    """
    if not click.confirm("This will delete all agent data AND pairing data. Continue?"):
        raise SystemExit(0)

    with _hub_session(host, port, user, password) as client:
        click.echo("Removing /data/agent and /data/iris, then rebooting...")
        client.exec_command("rm -rf /data/agent /data/iris && /sbin/reboot")
        click.echo(f"Agent reset initiated on {host}.")


@agent.command()
@click.argument("host")
@click.argument("tarfile", type=click.Path(exists=True, path_type=Path))
@_hub_options
def install(host, tarfile, port, user, password):
    """Install a new agent tarball on a hub. Uploads the tarball, removes /data/agent, and reboots.

    Preserves pairing data in /data/iris. HOST can be an IP, hostname, or hub ID.

    \b
    Examples:
      arcushub agent install LWR-2389 iris-agent-hub.tgz
      arcushub agent install 10.0.1.5 ./build/iris-agent-hub.tar.gz
    """
    tmp_path = "/tmp/iris-agent-hub"

    with _hub_session(host, port, user, password) as client:
        with open(tarfile, "rb") as f:
            _upload(client, f, tarfile.stat().st_size, tmp_path, f"Uploading {tarfile} → {tmp_path}")

        with _spinner("Installing agent and rebooting"):
            chan = client.get_transport().open_session()
            chan.exec_command(f"PATH=/home/root/bin:$PATH agent_install {tmp_path}")
            err = io.BytesIO()
            status = _pump(chan, io.BytesIO(), err)
            # agent_install ends with hub_restart, which usually drops the
            # connection before an exit status arrives (-1)
            if status not in (0, -1):
                msg = err.getvalue().decode(errors="replace").strip() or f"exit code {status}"
                raise click.ClickException(f"agent_install failed: {msg}")
        click.echo(f"Agent installed on {host}.")


@agent.command()
@click.argument("host")
@click.argument("tarfile", type=click.Path(exists=True, path_type=Path))
@_hub_options
def test(host, tarfile, port, user, password):
    """Upload and hot-swap an agent tarball without rebooting.

    Stops the agent, extracts the new tarball over /data/agent, and restarts it.
    Useful for rapid iteration during development.

    \b
    Examples:
      arcushub agent test LWR-2389 iris-agent-hub.tgz
      arcushub agent test 10.0.1.5 ./build/iris-agent-hub.tar.gz
    """
    tmp_path = "/tmp/iris-agent-hub"

    with _hub_session(host, port, user, password) as client:
        with open(tarfile, "rb") as f:
            _upload(client, f, tarfile.stat().st_size, tmp_path, f"Uploading {tarfile} → {tmp_path}")

        install_cmd = (
            "killall java; "
            "cd /data/agent && "
            "rm -rf lib bin conf libs && rm -f * && "
            f"tar xf {tmp_path} && "
            "chown -R agent . && chgrp -R agent . && "
            "/home/root/bin/agent_start"
        )
        with _spinner("Stopping agent, extracting, and restarting"):
            _run(client, install_cmd)
        click.echo(f"Agent restarted on {host}.")


_ARCUSPLATFORM_DIST = (
    Path.home() / "projects" / "arcusplatform" / "agent" / "arcus-agent" / "hub-v2" / "build" / "distributions"
)


@agent.command()
@click.argument("host")
@_hub_options
@click.option("--dist", type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to distTar directory (default: ~/projects/arcusplatform/.../distributions).")
@click.option("--all", "upload_all", is_flag=True, help="Upload all jars, not just changed ones.")
def update(host, port, user, password, dist, upload_all):
    """Update changed agent jars on a hub from the local distTar build.

    Compares jar files in the local distTar archive with those on the hub,
    uploads only the ones that differ (by MD5), and restarts the agent.

    \b
    Examples:
      arcushub agent update LWR-2389
      arcushub agent update LWR-2389 --all
      arcushub agent update 10.0.1.5 --dist /path/to/distributions
    """
    import tarfile as tarfile_mod

    dist_dir = dist or _ARCUSPLATFORM_DIST
    if not dist_dir.exists():
        raise click.ClickException(f"Distribution directory not found: {dist_dir}")

    # Find the tarball
    tarballs = sorted(dist_dir.glob("*.tar.gz")) + sorted(dist_dir.glob("*.tgz"))
    if not tarballs:
        raise click.ClickException(f"No .tar.gz or .tgz files found in {dist_dir}")
    tarball = tarballs[-1]
    click.echo(f"Using {tarball.name}")

    # Hash every jar in the tarball: {name: (md5, size)}
    local_jars = {}
    with tarfile_mod.open(tarball, "r:gz") as tf:
        for member in tf.getmembers():
            if member.name.startswith("libs/") and member.name.endswith(".jar"):
                jar_name = member.name[5:]  # strip "libs/"
                digest = hashlib.md5(tf.extractfile(member).read()).hexdigest()
                local_jars[jar_name] = (digest, member.size)

    if not local_jars:
        raise click.ClickException("No jars found in tarball.")

    with _hub_session(host, port, user, password) as client:
        with _spinner("Hashing hub jars"):
            output = _run(client, "md5sum /data/agent/libs/*.jar 2>/dev/null", check=False)

        # md5sum lines look like "<hash>  /data/agent/libs/foo.jar"
        remote_jars = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].endswith(".jar"):
                remote_jars[parts[1].rsplit("/", 1)[-1]] = parts[0]

        # Determine which jars need updating
        if upload_all:
            changed = sorted(local_jars)
        else:
            changed = [name for name, (digest, _size) in sorted(local_jars.items())
                       if remote_jars.get(name) != digest]

        if not changed:
            click.echo("All jars are up to date.")
            return

        click.echo(f"{len(changed)} jar{'s' if len(changed) != 1 else ''} to update:")
        for jar_name in changed:
            marker = "~" if jar_name in remote_jars else "+"
            click.echo(f"  {marker} {jar_name} ({_format_size(local_jars[jar_name][1])})")

        # Stop the agent before uploading; killall exits nonzero when java isn't running
        with _spinner("Stopping agent"):
            _run(client, "killall java", check=False)

        # Extract and upload changed jars
        with tarfile_mod.open(tarball, "r:gz") as tf:
            for jar_name in changed:
                jar_data = tf.extractfile(tf.getmember(f"libs/{jar_name}")).read()
                remote_path = f"/data/agent/libs/{jar_name}"
                _upload(client, io.BytesIO(jar_data), len(jar_data), remote_path, f"Uploading {jar_name}")

        # Fix ownership and restart
        with _spinner("Restarting agent"):
            _run(client, "chown agent:agent /data/agent/libs/*.jar && /home/root/bin/agent_start")

        click.echo(f"Updated {len(changed)} jar{'s' if len(changed) != 1 else ''} on {host}.")


@agent.command()
@click.argument("host")
@click.argument("key", required=False, default=None)
@click.argument("value", required=False, default=None)
@_hub_options
def config(host, key, value, port, user, password):
    """Get, set, or list hub database config values.

    HOST can be an IP address, hostname, or hub ID.

    \b
    Examples:
      arcushub agent config 10.0.1.5                          # list all keys
      arcushub agent config LWR-2389 iris.gateway.uri         # get value
      arcushub agent config LWR-2389 iris.gateway.uri wss://… # set value
    """
    db_path = "/data/iris/db/iris.db"

    if value is not None:
        # Set mode
        sql_key = key.replace("'", "''")
        sql_val = value.replace("'", "''")
        sql = (
            f"INSERT OR REPLACE INTO config (key,value,lastUpdateTime,lastReportTime) "
            f"VALUES ('{sql_key}','{sql_val}',0,0);"
        )
    elif key is not None:
        # Get mode
        sql_key = key.replace("'", "''")
        sql = f"SELECT value FROM config WHERE key='{sql_key}';"
    else:
        # List mode
        sql = "SELECT key, value FROM config ORDER BY key;"

    cmd = f"sqlite3 {db_path} {shlex.quote(sql)}"

    with _hub_session(host, port, user, password) as client:
        text = _run(client, cmd).strip()
        if value is not None:
            click.echo(f"Set {key}={value}")
        elif text:
            click.echo(text)
        elif key is not None:
            click.echo(f"No config entry for '{key}'.")


cli.add_command(agent)


@cli.command()
@click.argument("src")
@click.argument("dst")
@_hub_options
def scp(src, dst, port, user, password):
    """Copy files to/from a hub over SSH.

    Use HOST:PATH syntax for remote paths, where HOST can be an IP or hub ID.

    \b
    Examples:
      arcushub scp firmware.bin LWR-2389:/tmp/
      arcushub scp 10.0.1.5:/var/log/messages ./messages
    """
    def parse_remote(path):
        """Split HOST:PATH, returns (host, remote_path) or (None, local_path)."""
        # Avoid splitting on Windows drive letters (C:\) or bare paths
        if ":" in path and not path.startswith("/") and not path.startswith("."):
            host_part, _, remote_path = path.partition(":")
            if host_part:
                return host_part, remote_path
        return None, path

    src_host, src_path = parse_remote(src)
    dst_host, dst_path = parse_remote(dst)

    if src_host and dst_host:
        raise click.ClickException("Cannot specify remote paths for both source and destination.")
    if not src_host and not dst_host:
        raise click.ClickException("One of source or destination must be a remote path (HOST:PATH).")

    # Validate local file/directory exists before connecting
    if src_host:
        # Downloading: validate local destination directory
        dst_dir = Path(dst_path) if Path(dst_path).is_dir() else Path(dst_path).parent
        if not dst_dir.exists():
            raise click.ClickException(f"Local directory does not exist: {dst_dir}")
    else:
        # Uploading: validate local source file exists
        if not Path(src_path).exists():
            raise click.ClickException(f"Local file not found: {src_path}")

    with _hub_session(src_host or dst_host, port, user, password) as client:
        if src_host:
            if Path(dst_path).is_dir():
                dst_path = str(Path(dst_path) / Path(src_path).name)
            _download(client, src_path, Path(dst_path), f"Downloading {src_path} → {dst_path}")
        else:
            # If remote path is a directory, append the source filename
            if _run(client, f"test -d {shlex.quote(dst_path)} && echo dir", check=False).strip() == "dir":
                dst_path = dst_path.rstrip("/") + "/" + Path(src_path).name

            # Verify remote directory exists before transferring
            remote_dir = dst_path.rsplit("/", 1)[0] if "/" in dst_path else "."
            if _run(client, f"test -d {shlex.quote(remote_dir)} && echo dir", check=False).strip() != "dir":
                raise click.ClickException(f"Remote directory does not exist: {remote_dir}")

            with open(src_path, "rb") as f:
                _upload(client, f, Path(src_path).stat().st_size, dst_path, f"Uploading {src_path} → {dst_path}")


@cli.command()
@click.argument("host")
@click.argument("firmware", type=click.Path(exists=True, path_type=Path))
@_hub_options
@click.option("-k", "--kill-agent", is_flag=True, help="Kill agent before installing radio firmware.")
@click.option("-s", "--skip-radio", is_flag=True, help="Skip install of radio firmware.")
@click.option("-w", "--wipe-agent", is_flag=True, help="Remove /data/agent before installing firmware.")
def flash(host, firmware, port, user, password, kill_agent, skip_radio, wipe_agent):
    """Upload and install firmware on a hub. HOST can be an IP, hostname, or hub ID.

    \b
    Examples:
      arcushub flash LWR-2389 hub/v2/firmware/hubOS_2.2.0.009.bin
      arcushub flash 10.0.1.5 hub/v3/firmware/hubOSv3_3.0.1.025.bin
    """
    with _hub_session(host, port, user, password) as client:
        # Ensure upload directory exists; fall back to /tmp if
        # /data/iris/data/tmp cannot be created (agent may be broken).
        remote_dir = "/data/iris/data/tmp"
        result = _run(client, f"mkdir -p {remote_dir} && chown agent:agent {remote_dir} 2>/dev/null && echo ok",
                      check=False)
        if result.strip() != "ok":
            remote_dir = "/tmp"
        remote_path = f"{remote_dir}/hubOS.bin"

        # Upload firmware via exec channel (hub SSH lacks SFTP)
        with open(firmware, "rb") as f:
            _upload(client, f, firmware.stat().st_size, remote_path, f"Uploading {firmware.name} → {remote_path}")

        # Detect signed firmware (non-gzip) vs unsigned archive (gzip)
        with open(firmware, "rb") as f:
            signed = f.read(2) != b"\x1f\x8b"

        if signed:
            cmd_parts = ["update", "-f"]
            if kill_agent:
                cmd_parts.append("-k")
            cmd_parts.append(f"file://{remote_path}")
        else:
            cmd_parts = ["fwinstall"]
            if kill_agent:
                cmd_parts.append("-k")
            if skip_radio:
                cmd_parts.append("-s")
            cmd_parts.append(remote_path)
        cmd = " ".join(cmd_parts)

        click.echo(f"Installing: {cmd}")
        chan = client.get_transport().open_session()
        chan.exec_command(cmd)
        exit_status = _pump(chan, sys.stdout.buffer, sys.stderr.buffer)
        if exit_status != 0:
            raise click.ClickException(f"Firmware install failed (exit code {exit_status})")
        if wipe_agent:
            with _spinner("Stopping agent"):
                _run(client, "/home/root/bin/agent_stop", check=False)
            with _spinner("Wiping /data/agent"):
                _run(client, "rm -rf /data/agent")

        # Clean up uploaded firmware
        _run(client, f"rm -f {remote_path}", check=False)

        click.echo("Firmware install complete. Rebooting...")
        client.exec_command("/sbin/reboot")


@cli.command()
@click.argument("host")
@_hub_options
@click.option("-f", "--follow", is_flag=True, help="Follow the log in real time (like tail -f).")
@click.option("-n", "--lines", default=50, help="Number of lines to show when following.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Save log to this file (default: hubAgent.log).")
def logs(host, port, user, password, follow, lines, output):
    """Download or follow /tmp/hubAgent.log on a hub. HOST can be an IP, hostname, or hub ID.

    By default, downloads the full log file. Use -f to follow in real time.

    \b
    Examples:
      arcushub logs LWR-2389              # download full log
      arcushub logs LWR-2389 -o hub.log   # download to specific file
      arcushub logs LWR-2389 -f           # follow log in real time
      arcushub logs LWR-2389 -f -n 100    # follow, showing last 100 lines
    """
    remote_path = "/tmp/hubAgent.log"

    with _hub_session(host, port, user, password) as client:
        if follow:
            chan = client.get_transport().open_session()
            chan.exec_command(f"tail -n {lines} -f {remote_path}")
            try:
                _pump(chan, sys.stdout.buffer, sys.stderr.buffer)
            except KeyboardInterrupt:
                pass
        else:
            local_path = output or Path("hubAgent.log")
            _download(client, remote_path, local_path, f"Downloading {remote_path} → {local_path}")

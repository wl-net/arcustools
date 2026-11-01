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
import time
from contextlib import contextmanager, suppress
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
    """Show a braille spinner with a message while work runs in the block.

    Status goes to stderr, so stdout carries only a command's result. Unless stderr
    is a terminal there's no animation, just one line when the work is done.
    """
    stop = threading.Event()
    failed = threading.Event()
    animate = sys.stderr.isatty()
    clear = "\r\033[K" if animate else ""

    def spin():
        i = 0
        while animate and not stop.is_set():
            frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
            suffix = f"  {progress.status()}" if progress else ""
            click.echo(f"{clear}{frame} {message}{suffix}", nl=False, err=True)
            i += 1
            stop.wait(0.08)
        stop.wait()
        suffix = f"  {progress.status()}" if progress else ""
        mark = "✘" if failed.is_set() else "✔"
        click.echo(f"{clear}{mark} {message}{suffix}", err=True)

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


def _load_cache(path: Path | None = None) -> dict:
    path = path or _CACHE_PATH
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_cache(cache: dict, path: Path | None = None) -> None:
    path = path or _CACHE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache))


def _hub_uuids_path() -> Path:
    return _CACHE_PATH.with_name("hub_uuids.json")


def _is_reachable(ip: str, port: int = 22, timeout: float = 1.0) -> bool:
    """Quick TCP connect check."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _answers(ip: str, port: int = 22, timeout: float = 2.5) -> bool:
    """Is a host up at ip? A refused connection counts: it took a live host to refuse.

    Hubs with SSH closed take macOS just over a second to report as refused, so
    the timeout has to be longer than _is_reachable's to see that answer at all.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except ConnectionRefusedError:
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
        result = subprocess.run(["arp", "-an"], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return []
    return _parse_arp_a(result.stdout)


def _arcus_oui_prefixes() -> set[str]:
    """The known Arcus OUIs as lowercase `xx:xx:xx` MAC prefixes."""
    from .hubid import KNOWN_OUIS

    return {f"{(oui >> 16) & 0xFF:02x}:{(oui >> 8) & 0xFF:02x}:{oui & 0xFF:02x}" for oui in KNOWN_OUIS}


def _find_all_hubs_in_arp() -> list[tuple[str, str]]:
    """Scan ARP table for all MACs matching known Arcus OUIs. Returns [(ip, mac), ...]."""
    oui_prefixes = _arcus_oui_prefixes()
    return [(ip, mac) for ip, mac in _read_arp() if mac[:8] in oui_prefixes]


def _find_in_arp(mac_even: str, mac_odd: str) -> str | None:
    """Search the ARP table for a MAC, return the IP or None."""
    for ip, mac in _read_arp():
        if mac in (mac_even, mac_odd):
            return ip
    return None


def _find_live_in_arp(mac_even: str, mac_odd: str, port: int = 22) -> str | None:
    """Find a MAC in the ARP table, as long as that entry is still current.

    An entry can outlive a DHCP change. Traffic to its IP goes to the MAC on
    record, so an answer means the pairing holds, unless the probe made the
    kernel relearn the entry, which is why the table is read again.
    """
    ip = _find_in_arp(mac_even, mac_odd)
    if ip and _answers(ip, port) and _find_in_arp(mac_even, mac_odd) == ip:
        return ip
    return None


# Hubs answer SSDP as "Iris OS/2.0 UPnP/1.0 Iris/2.0"; other UPnP devices on the
# network (media renderers, routers) name themselves in the same header.
_HUB_SSDP_SERVER = re.compile(r"iris|arcus", re.IGNORECASE)
_USN_UUID = re.compile(r"uuid:([0-9a-f-]{36})", re.IGNORECASE)
_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


def _ssdp_hub_candidates(responses: list[dict]) -> list[str]:
    """IPs of SSDP responders that look like Arcus hubs, in response order, deduplicated."""
    ips = []
    for response in responses:
        ip = response.get("_ip")
        if ip and ip not in ips and _HUB_SSDP_SERVER.search(response.get("server", "")):
            ips.append(ip)
    return ips


def _ssdp_hub_uuids(responses: list[dict]) -> dict[str, str]:
    """Map the IP of each hub-like SSDP responder to the UUID in its USN header."""
    uuids = {}
    for response in responses:
        match = _USN_UUID.match(response.get("usn", ""))
        if match and response.get("_ip") in _ssdp_hub_candidates([response]):
            uuids[response["_ip"]] = match.group(1).lower()
    return uuids


# The UUID a hub announces doesn't carry its hub ID, but it does outlive a DHCP
# change: the agent derives it from the hub's certificate (IrisUpnpService). So
# once a hub is identified, its UUID is enough to recognise it without ARP or SSH.
def _known_hubs(responses: list[dict]) -> dict[str, str]:
    """Map the IP of each responder announcing a UUID seen before to that hub's MAC."""
    known = _load_cache(_hub_uuids_path())
    return {ip: known[uuid] for ip, uuid in _ssdp_hub_uuids(responses).items() if uuid in known}


def _remember_hubs(responses: list[dict], found: list[tuple[str, str]]) -> None:
    """Record the announced UUID of each identified hub in found, [(ip, mac), ...]."""
    uuids = _ssdp_hub_uuids(responses)
    seen = {uuids[ip]: mac for ip, mac in found if ip in uuids}
    if seen:
        known = _load_cache(_hub_uuids_path())
        known.update(seen)
        _save_cache(known, _hub_uuids_path())


def _remember_arp_hubs(responses: list[dict], port: int = 22) -> None:
    """Record hubs the ARP table can name, once their entries prove current.

    What's saved here is used long after the table may have stopped being readable,
    so a stale entry would mean recognising one hub as another with nothing to catch it.
    """
    uuids = _ssdp_hub_uuids(responses)
    known = _known_hubs(responses)
    unconfirmed = {ip for ip, mac in _find_all_hubs_in_arp() if ip in uuids and known.get(ip) != mac}
    live = {ip for ip in unconfirmed if _answers(ip, port)}
    _remember_hubs(responses, [(ip, mac) for ip, mac in _find_all_hubs_in_arp() if ip in live])


def _parse_iface_macs(text: str) -> dict[str, str]:
    """Parse `<path>/<iface>/address <mac>` lines into {iface: mac}, skipping junk."""
    macs = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or not _MAC_RE.match(fields[1]):
            continue
        parts = fields[0].split("/")
        iface = parts[-2] if len(parts) >= 2 else fields[0]
        macs[iface] = _normalize_mac(fields[1])
    return macs


_ARP_EMPTY_NOTE = (
    "The system ARP table came back empty, so a hub not seen before can only be identified"
    " over SSH. This happens on macOS 27 under Homebrew python, which pipx installs default"
    " to. Once identified, a hub is recognised from then on by the UUID it announces."
)


def _unidentified_note(ips: list[str]) -> str:
    """Note for hub-like SSDP responders whose hub ID could not be read."""
    return (f"{len(ips)} hub(s) answered discovery but could not be identified ({', '.join(ips)}): "
            "a hub ID comes from the ARP table or SSH, and neither worked.")


def _echo_unidentified(ips: list[str]) -> None:
    """Report responders that could not be identified, and why if the ARP table is the cause."""
    click.echo(_unidentified_note(ips))
    if not _read_arp():
        click.echo(_ARP_EMPTY_NOTE)


_IDENTIFY_TIMEOUT = 10.0  # seconds a logged-in hub gets to report its MACs


def _identify_hub(ip: str, port: int = 22, user: str = "root",
                  password: str | None = None) -> tuple[str, str] | None:
    """Ask the host at ip for its MAC over SSH. Returns (hub_id, mac), or None.

    This is the fallback for when the ARP table can't supply the MAC. Anything
    that refuses SSH, or whose MACs carry no known Arcus OUI, returns None.
    """
    from .hubid import mac_to_hub_id
    from .ssh import connect

    if not _is_reachable(ip, port=port):
        return None
    try:
        client = connect(ip, port=port, user=user, password=password)
    except Exception:
        return None
    # A hub that drops off mid-probe never closes the channel, and nothing below
    # has a timeout of its own. Closing the client ends every wait it could be in.
    deadline = threading.Timer(_IDENTIFY_TIMEOUT, client.close)
    deadline.daemon = True
    deadline.start()
    try:
        out = _run(client, "for f in /sys/class/net/*/address; do echo $f $(cat $f); done", check=False)
    except Exception:
        return None  # a hub that drops mid-probe shouldn't stop us asking the next one
    finally:
        deadline.cancel()
        client.close()

    oui_prefixes = _arcus_oui_prefixes()
    macs = _parse_iface_macs(out)
    # eth0 carries the MAC the hub ID is derived from; check it first.
    for _, mac in sorted(macs.items(), key=lambda kv: kv[0] != "eth0"):
        if mac[:8] in oui_prefixes:
            return mac_to_hub_id(mac), mac
    return None


def _connect(host: str, port: int = 22, user: str = "root", password: str | None = None):
    """Connect to a hub via SSH, showing a spinner during the handshake."""
    from .ssh import connect

    with _spinner(f"Connecting to {user}@{host}:{port}"):
        client = connect(host, port=port, user=user, password=password)
    # Keepalives make a hub that reboots or drops off the network fail the
    # connection instead of leaving reads waiting forever.
    client.get_transport().set_keepalive(15)
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
    ip = _resolve_host(host, port=port, user=user, password=password)
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
        if chan.closed and not chan.recv_ready() and not chan.recv_stderr_ready():
            return -1


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
        # The connection may be what failed, and that error is the one to report
        with suppress(Exception):
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


def _resolve_host(host: str, timeout: float = 5.0, port: int = 22,
                  user: str = "root", password: str | None = None) -> str:
    """If host is a hub ID, find its IP on the network. Otherwise return as-is.

    Resolution order:
    1. Check local cache (~/.cache/arcushub/hosts.json) + quick TCP probe
    2. Check ARP table, and that the entry is still current
    3. SSDP discovery (slow, populates ARP table) + check ARP again
    4. Ask the hubs that answered SSDP for their MAC over SSH, falling back on
       the UUID a hub announced if it was seen before and SSH can't settle it

    Step 4 exists because the ARP table is not always readable. On macOS 27
    Homebrew python (and so pipx installs on top of it) gets an empty table with
    no error, and so does any child it spawns, which rules out shelling out to
    a tool that could read it. Every MAC lookup then comes up empty.
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

    # 1. Check cache. DHCP may have handed the cached IP to a different hub
    # since, so confirm it is still this one: by MAC if the ARP table has that IP
    # (the probe above refreshes the entry), else by asking the host. The table
    # may be unreadable, or have no entry because the hub is behind a router.
    cache = _load_cache()
    cached_ip = cache.get(hub_id)
    if cached_ip and _is_reachable(cached_ip, port=port):
        cached_mac = dict(_read_arp()).get(cached_ip)
        if cached_mac in (mac_even, mac_odd):
            return cached_ip
        if cached_mac is None:
            identified = _identify_hub(cached_ip, port, user, password)
            if identified and identified[0] == hub_id:
                return cached_ip

    click.echo(f"Resolving {hub_id} (MAC {mac_even} or {mac_odd})...", err=True)

    # 2. Check ARP table (already populated from recent traffic)
    ip = _find_live_in_arp(mac_even, mac_odd, port)
    if ip:
        cache[hub_id] = ip
        _save_cache(cache)
        return ip

    # 3. SSDP discovery to populate ARP table, then check again
    with _spinner("Running SSDP discovery"):
        responses = discover(timeout=timeout)

    _remember_arp_hubs(responses, port)
    ip = _find_live_in_arp(mac_even, mac_odd, port)
    if ip:
        cache[hub_id] = ip
        _save_cache(cache)
        return ip

    # 4. Ask the hubs that answered which hub they are. A remembered UUID says who
    # to ask first: a hub believed to be this one, then strangers, then hubs believed
    # to be another, who only matter if that belief is wrong. SSH overrules a UUID,
    # which can't be checked any other way, but with SSH closed it's all there is.
    known = _known_hubs(responses)

    def rank(ip):
        if ip not in known:
            return 1
        return 0 if known[ip] in (mac_even, mac_odd) else 2

    match = None
    others, unidentified = [], []
    for candidate in sorted(_ssdp_hub_candidates(responses), key=rank):
        with _spinner(f"Identifying hub at {candidate}"):
            identified = _identify_hub(candidate, port, user, password)
        if identified:
            cache[identified[0]] = candidate  # worth caching whoever answered
            _remember_hubs(responses, [(candidate, identified[1])])
            if identified[0] == hub_id:
                match = candidate
                break
            others.append(candidate)
        elif rank(candidate) == 0:
            cache[hub_id] = candidate
            match = candidate
            break
        elif candidate in known:
            others.append(candidate)
        else:
            unidentified.append(candidate)
    _save_cache(cache)
    if match:
        return match

    msg = f"Hub {hub_id} not found on the network."
    if others:
        msg += f" {len(others)} hub(s) answered discovery ({', '.join(others)}), none of them this one."
    if unidentified:
        # Any of these may be the hub we want; all we know is that we can't tell.
        msg += f" {_unidentified_note(unidentified)}"
    if not _read_arp():
        msg += f"\n{_ARP_EMPTY_NOTE}\nYou can also pass the hub's IP address instead of its ID."
    raise click.ClickException(msg)


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
    from .ssh import key_login_works, remember_key

    chosen = key is not None  # the auto-detected names are ones logins already try
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

    private_key = key.with_suffix("").resolve()
    ip = _resolve_host(host, port=port, user=user, password=password)
    with _hub_session(ip, port, user, password) as client:
        auth_keys = "/data/config/dropbear/authorized_keys"
        quoted_key = shlex.quote(key_content)
        # Logins read this copy, which the hub otherwise only makes at boot
        publish = f"cp {auth_keys} /var/run/authorized_keys && chmod 600 /var/run/authorized_keys"
        # Print a marker only when appending, so re-running doesn't duplicate the key
        cmd = (
            f"mkdir -p /data/config/dropbear && touch {auth_keys} && "
            f"(grep -qxF {quoted_key} {auth_keys} || (echo {quoted_key} >> {auth_keys} && echo added)) && "
            f"{publish}"
        )
        added = _run(client, cmd).strip() == "added"

        if not key_login_works(ip, port, user, private_key):
            # A hub with SSH enabled and any key at all goes key-only, so leaving
            # one that doesn't work would lock out every password login.
            if added:
                _run(client, f"grep -vxF {quoted_key} {auth_keys} > {auth_keys}.new; "
                             f"mv -f {auth_keys}.new {auth_keys} && {publish}")
            undone = ", so the key was taken back off the hub" if added else ""
            raise click.ClickException(
                f"Logging in with {private_key} failed{undone}."
                " arcushub needs an unencrypted key file, because it doesn't use the SSH agent."
            )
    if chosen:
        remember_key(private_key)
    if added:
        click.echo("SSH key installed. You can now connect without a password.")
    else:
        click.echo("SSH key already installed.")


@cli.command()
@click.argument("hub_id")
@click.option("--timeout", "-t", default=5.0, help="SSDP discovery timeout in seconds.")
@_hub_options
def find(hub_id, timeout, port, user, password):
    """Find a hub's IP address on the local network by its hub ID."""
    ip = _resolve_host(hub_id, timeout=timeout, port=port, user=user, password=password)
    click.echo(ip)


@cli.command()
@click.option("--timeout", "-t", default=5.0, help="SSDP discovery timeout in seconds.")
@_hub_options
def hubs(timeout, port, user, password):
    """Discover all Arcus hubs on the local network."""
    from .hubid import mac_to_hub_id
    from .ssdp import discover

    with _spinner("Running SSDP discovery"):
        responses = discover(timeout=timeout)

    _remember_arp_hubs(responses, port)
    found = _find_all_hubs_in_arp()
    in_arp = {ip for ip, _ in found}
    known = _known_hubs(responses)
    unidentified = []
    # The ARP table can't name every hub that answered: it may be unreadable (see
    # _resolve_host), or just not list them all. Recognise the hubs seen before
    # and ask the rest.
    for ip in _ssdp_hub_candidates(responses):
        if ip in in_arp:
            continue
        if ip in known:
            found.append((ip, known[ip]))
            continue
        with _spinner(f"Identifying hub at {ip}"):
            identified = _identify_hub(ip, port, user, password)
        if identified:
            found.append((ip, identified[1]))
            _remember_hubs(responses, [(ip, identified[1])])
        else:
            unidentified.append(ip)
    # A hub in the table at an old IP and answering at a new one is one hub, at the new IP
    found = list({mac: (ip, mac) for ip, mac in found}.values())
    if not found:
        if unidentified:
            _echo_unidentified(unidentified)
        else:
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
    if unidentified:
        click.echo()
        _echo_unidentified(unidentified)


@cli.command()
@click.argument("host")
@_hub_options
def ping(host, port, user, password):
    """Ping a hub and show basic status. HOST can be an IP, hostname, or hub ID."""
    host = _resolve_host(host, port=port, user=user, password=password)

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

        # The agent is the hub's only JVM
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


_AGENT_LIBS_DIR = "/data/agent/libs"
_JAR_STAGING_DIR = "/data/agent/libs.new"
_JAR_BACKUP_DIR = "/data/agent/libs.old"
_AGENT_JSA = "/data/agent/agent.jsa"
_AGENT_RESTART_TIMEOUT = 30.0

# irisagentd supervises the agent, restarting it the moment it exits, so `killall
# java` is how to restart it; irisinitd does the same. Avoid agent_stop, which kills
# the supervisor too, and agent_start, whose replacement didn't outlive the SSH
# session on a real hub and lacks the memory limits this script sets for it.
_SUPERVISOR_START = "/etc/init.d/irisagent </dev/null >/dev/null 2>&1"
_AGENT_RESTART = f"killall java; pidof irisagentd >/dev/null || {_SUPERVISOR_START}"


def _restart_agent(client) -> None:
    """Restart the agent, and wait for a new one to be running."""
    before = _run(client, "pidof java", check=False).split()
    with _spinner("Restarting agent"):
        _run(client, _AGENT_RESTART)
        deadline = time.monotonic() + _AGENT_RESTART_TIMEOUT
        while True:
            running = _run(client, "pidof java", check=False).split()
            if running and running != before:
                return
            if time.monotonic() > deadline:
                raise click.ClickException(
                    f"No new agent after {_AGENT_RESTART_TIMEOUT:.0f}s. See /tmp/hubAgent.log on the hub."
                )
            time.sleep(0.5)


def _hub_jars(client) -> dict[str, str]:
    """The jars in the agent's libs directory, as {name: md5}."""
    output = _run(client, f"md5sum {_AGENT_LIBS_DIR}/*.jar 2>/dev/null", check=False)
    jars = {}
    # md5sum lines look like "<hash>  /data/agent/libs/foo.jar"
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].endswith(".jar"):
            jars[parts[1].rsplit("/", 1)[-1]] = parts[0]
    return jars


def _jar_artifact(name: str) -> str:
    """A jar's name without its version: foo-bar-2.13.29-SNAPSHOT.jar is foo-bar."""
    return re.sub(r"-\d[\w.]*(-SNAPSHOT)?\.jar$", "", name)


def _other_versions(names, jars) -> list[str]:
    """The jars that are other versions of these names."""
    artifacts = {_jar_artifact(name) for name in names}
    return sorted(jar for jar in jars if jar not in names and _jar_artifact(jar) in artifacts)


def _stage_jars(client, jars) -> None:
    """Upload (name, data) pairs to a staging directory and check they arrived intact.

    The agent stays up meanwhile, so it keeps feeding the hardware watchdog and a
    failed upload changes nothing. The directory is beside libs, not in it, because
    the launch script puts every file in libs on the classpath.
    """
    _run(client, f"rm -rf {_JAR_STAGING_DIR} && mkdir -p {_JAR_STAGING_DIR}")
    try:
        for name, data in jars:
            remote_path = f"{_JAR_STAGING_DIR}/{name}"
            _upload(client, io.BytesIO(data), len(data), remote_path, f"Uploading {name}")
            digest = _run(client, f"md5sum {shlex.quote(remote_path)}").split()[0]
            if digest != hashlib.md5(data).hexdigest():
                raise click.ClickException(f"{name} arrived corrupted: md5 {digest} on the hub")
    except click.ClickException:
        with suppress(Exception):
            _run(client, f"rm -rf {_JAR_STAGING_DIR}", check=False)
        raise


def _swap_in_jars(client, names, remove=(), backup=()) -> None:
    """Move staged jars into libs, take out `remove`, and copy `backup` aside first.

    This must come before a restart, since irisagentd starts the next agent as soon
    as the last one dies. It's safe with the agent running: renaming over a jar leaves
    it with the old file still open. The shared class archive is built from the old
    jars and has to go too, or the next start fails on it before rebuilding it.
    """
    libs = [shlex.quote(f"{_AGENT_LIBS_DIR}/{name}") for name in backup]
    steps = [f"mkdir -p {_JAR_BACKUP_DIR}", f"cp -a {' '.join(libs)} {_JAR_BACKUP_DIR}/"] if libs else []
    if names:
        staged = " ".join(shlex.quote(f"{_JAR_STAGING_DIR}/{name}") for name in names)
        steps.append(f"mv -f {staged} {_AGENT_LIBS_DIR}/")
    if remove:
        steps.append("rm -f " + " ".join(shlex.quote(f"{_AGENT_LIBS_DIR}/{name}") for name in remove))
    steps += [f"chown agent:agent {_AGENT_LIBS_DIR}/*.jar", f"rm -f {_AGENT_JSA}", f"rmdir {_JAR_STAGING_DIR}"]
    with _spinner("Swapping in jars"):
        _run(client, " && ".join(steps))


@agent.command()
@click.argument("host")
@_hub_options
def restart(host, port, user, password):
    """Restart the hub agent. HOST can be an IP address, hostname, or hub ID."""
    with _hub_session(host, port, user, password) as client:
        _restart_agent(client)
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

        # The supervisor has to go too, or it would start the agent mid-extract
        install_cmd = (
            "/home/root/bin/agent_stop; "
            "cd /data/agent && "
            "rm -rf lib bin conf libs && rm -f * && "
            f"tar xf {tmp_path} && "
            "chown -R agent . && chgrp -R agent . && "
            f"{_SUPERVISOR_START}"
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
            remote_jars = _hub_jars(client)

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

        # Leftovers of an older build, not jars the tarball also ships
        outdated = _other_versions(changed, set(remote_jars) - set(local_jars))
        for jar_name in outdated:
            click.echo(f"  - {jar_name}")

        with tarfile_mod.open(tarball, "r:gz") as tf:
            _stage_jars(client, ((name, tf.extractfile(tf.getmember(f"libs/{name}")).read()) for name in changed))
        _swap_in_jars(client, changed, remove=outdated)
        _restart_agent(client)

        click.echo(f"Updated {len(changed)} jar{'s' if len(changed) != 1 else ''} on {host}.")


@agent.command()
@click.argument("host")
@click.argument("jars", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@_hub_options
@click.option("--replace", multiple=True, metavar="JAR",
              help="Jar on the hub to replace, when it isn't another version of the same name. Repeatable.")
@click.option("--no-restart", is_flag=True, help="Leave the new jars for the next restart.")
@click.option("--dry-run", is_flag=True, help="Show what would change without changing anything.")
def push(host, jars, port, user, password, replace, no_restart, dry_run):
    """Install locally built jars on a hub and restart the agent.

    Uploads with the agent running and checks each jar's MD5, so a failed push
    changes nothing. Then swaps the jars in, replacing any other version of the
    same jar, and restarts the agent. Replaced jars are kept in /data/agent/libs.old.

    HOST can be an IP, hostname, or hub ID.

    \b
    Examples:
      arcushub agent push LWR-2389 build/libs/arcus-zigbee-controller-2.13.29-SNAPSHOT.jar
      arcushub agent push LWR-2389 zigbee.jar zwave.jar --dry-run
      arcushub agent push LWR-2389 new.jar --replace old-2.13.25.jar --no-restart
    """
    local_jars = {path.name: path.read_bytes() for path in jars}
    digests = {name: hashlib.md5(data).hexdigest() for name, data in local_jars.items()}

    with _hub_session(host, port, user, password) as client:
        with _spinner("Hashing hub jars"):
            remote_jars = _hub_jars(client)

        missing = [jar for jar in replace if jar not in remote_jars]
        if missing:
            raise click.ClickException(f"Not on the hub, so can't be replaced: {', '.join(missing)}")
        outdated = [jar for jar in replace if jar not in local_jars]
        if not replace:
            outdated = _other_versions(local_jars, remote_jars)
            artifacts = [_jar_artifact(jar) for jar in outdated]
            clashes = sorted({jar for jar in outdated if artifacts.count(_jar_artifact(jar)) > 1})
            if clashes:
                raise click.ClickException(
                    f"Several jars on the hub could be the one to replace: {', '.join(clashes)}. Use --replace."
                )

        changed = [name for name in local_jars if remote_jars.get(name) != digests[name]]
        if not changed and not outdated:
            click.echo("Those jars are already on the hub.")
            return

        for name in changed:
            marker = "~" if name in remote_jars else "+"
            click.echo(f"  {marker} {name} ({_format_size(len(local_jars[name]))}, md5 {digests[name][:8]})")
        for name in outdated:
            click.echo(f"  - {name}")

        if dry_run:
            click.echo("Dry run: nothing changed.")
            return

        _stage_jars(client, ((name, local_jars[name]) for name in changed))
        backup = [name for name in changed if name in remote_jars] + outdated
        _swap_in_jars(client, changed, remove=outdated, backup=backup)
        if no_restart:
            click.echo(f"Jars installed on {host}. They'll load the next time the agent restarts.")
            return
        _restart_agent(client)
        click.echo(f"Jars installed on {host} and agent restarted.")


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
            remote_dir = (dst_path.rsplit("/", 1)[0] or "/") if "/" in dst_path else "."
            if _run(client, f"test -d {shlex.quote(remote_dir)} && echo dir", check=False).strip() != "dir":
                raise click.ClickException(f"Remote directory does not exist: {remote_dir}")

            with open(src_path, "rb") as f:
                _upload(client, f, Path(src_path).stat().st_size, dst_path, f"Uploading {src_path} → {dst_path}")


def _stop_agent_for_flash(client):
    """Stop the agent to free memory. Returns the channel feeding the watchdog in its place.

    validate_image/fwinstall stage the decrypted image in /tmp, which is RAM;
    with the Java agent also resident, the hub runs out of memory. The hub
    reboots after flashing anyway, so stop the agent up front.

    On release images only the agent feeds the hardware watchdog (300s on V2 hubs,
    120s on V3), and it leaves it armed when it exits. validate_image doesn't poke
    it (fwinstall does), so feed it ourselves until the install finishes. Capped
    at 30 minutes in case we lose the connection.
    """
    with _spinner("Stopping agent to free memory"):
        _run(client, "/home/root/bin/agent_stop", check=False)
    feeder = client.get_transport().open_session()
    feeder.exec_command("i=0; while [ $i -lt 30 ]; do echo A > /dev/watchdog0; i=$((i+1)); sleep 60; done")
    return feeder


@cli.command()
@click.argument("host")
@click.argument("firmware", type=click.Path(exists=True, path_type=Path))
@_hub_options
@click.option("-k", "--kill-agent", is_flag=True, help="Pass -k to update/fwinstall (kill agent before radio install).")
@click.option("-s", "--skip-radio", is_flag=True, help="Skip install of radio firmware (unsigned archives only).")
@click.option("-w", "--wipe-agent", is_flag=True, help="Remove /data/agent after installing firmware.")
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
        feeder = None
        if result.strip() != "ok":
            remote_dir = "/tmp"
            feeder = _stop_agent_for_flash(client)  # the image itself will be in RAM
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

        if feeder is None:
            feeder = _stop_agent_for_flash(client)

        click.echo(f"Installing: {cmd} (this takes several minutes; do not interrupt)")
        chan = client.get_transport().open_session()
        # update/fwinstall print progress without flushing, so on a plain pipe
        # nothing appears until they exit; a PTY makes their stdout line-buffered.
        chan.get_pty()
        chan.exec_command(cmd)
        exit_status = _pump(chan, sys.stdout.buffer, sys.stderr.buffer)
        feeder.close()
        if exit_status != 0:
            raise click.ClickException(
                f"Firmware install failed (exit code {exit_status}); agent is stopped, reboot the hub to restart it"
            )
        if wipe_agent:
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

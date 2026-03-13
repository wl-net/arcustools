import sys
import threading
import time
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


@contextmanager
def _spinner(message: str, progress: _Progress | None = None):
    """Show a braille spinner with a message while work runs in the block."""
    stop = threading.Event()

    def spin():
        i = 0
        while not stop.is_set():
            frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
            suffix = f"  {progress.status()}" if progress else ""
            click.echo(f"\r\033[K{frame} {message}{suffix}", nl=False)
            i += 1
            stop.wait(0.08)
        suffix = f"  {progress.status()}" if progress else ""
        click.echo(f"\r\033[K✔ {message}{suffix}")

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        yield
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
    import re
    return bool(re.match(r"^[A-Za-z]{2,3}-\d{4}$", value))


def _load_cache() -> dict:
    import json
    if _CACHE_PATH.exists():
        try:
            return json.loads(_CACHE_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_cache(cache: dict) -> None:
    import json
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CACHE_PATH.write_text(json.dumps(cache))


def _is_reachable(ip: str, port: int = 22, timeout: float = 1.0) -> bool:
    """Quick TCP connect check."""
    import socket
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _find_all_hubs_in_arp() -> list[tuple[str, str]]:
    """Scan ARP table for all MACs matching known Arcus OUIs. Returns [(ip, mac), ...]."""
    from .hubid import KNOWN_OUIS

    oui_prefixes = set()
    for oui in KNOWN_OUIS:
        oui_prefixes.add(f"{(oui >> 16) & 0xFF:02x}:{(oui >> 8) & 0xFF:02x}:{oui & 0xFF:02x}")

    results = []

    # Try /proc/net/arp first (Linux)
    try:
        with open("/proc/net/arp") as f:
            for line in f.read().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 4:
                    ip_addr = fields[0]
                    raw_mac = fields[3]
                    if raw_mac == "00:00:00:00:00:00":
                        continue
                    norm = ":".join(f"{int(b, 16):02x}" for b in raw_mac.split(":"))
                    if norm[:8] in oui_prefixes:
                        results.append((ip_addr, norm))
        return results
    except OSError:
        pass

    # Fall back to arp command (macOS, BSDs)
    import re
    import subprocess
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    except FileNotFoundError:
        return results
    for line in result.stdout.splitlines():
        arp_mac_match = re.search(r"at\s+([0-9a-f:]+)", line.lower())
        if not arp_mac_match:
            continue
        arp_mac = ":".join(f"{int(b, 16):02x}" for b in arp_mac_match.group(1).split(":"))
        if arp_mac[:8] in oui_prefixes:
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if m:
                results.append((m.group(1), arp_mac))
    return results


def _find_in_arp(mac_even: str, mac_odd: str) -> str | None:
    """Search the ARP table for a MAC, return the IP or None."""
    import re

    # Try /proc/net/arp first (Linux, no external dependency)
    try:
        with open("/proc/net/arp") as f:
            for line in f.read().splitlines()[1:]:  # skip header
                fields = line.split()
                if len(fields) >= 4:
                    ip_addr = fields[0]
                    raw_mac = fields[3]
                    if raw_mac == "00:00:00:00:00:00":
                        continue
                    norm = ":".join(f"{int(b, 16):02x}" for b in raw_mac.split(":"))
                    if norm in (mac_even, mac_odd):
                        return ip_addr
    except OSError:
        pass

    # Fall back to arp command (macOS, BSDs)
    import subprocess
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    except FileNotFoundError:
        return None
    for line in result.stdout.splitlines():
        arp_mac_match = re.search(r"at\s+([0-9a-f:]+)", line.lower())
        if not arp_mac_match:
            continue
        arp_mac = ":".join(f"{int(b, 16):02x}" for b in arp_mac_match.group(1).split(":"))
        if arp_mac in (mac_even, mac_odd):
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if m:
                return m.group(1)
    return None


def _connect(host: str, port: int = 22, user: str = "root", password: str | None = None):
    """Connect to a hub via SSH, showing a spinner during the handshake."""
    from .ssh import connect

    with _spinner(f"Connecting to {user}@{host}:{port}"):
        client = connect(host, port=port, user=user, password=password)
    return client


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
    mac = hub_id_to_mac(hub_id)
    mac_bytes = bytes(int(b, 16) for b in mac.split(":"))
    mac_even = ":".join(f"{b:02x}" for b in mac_bytes)
    mac_odd = ":".join(f"{b:02x}" for b in mac_bytes[:-1]) + f":{mac_bytes[-1] | 1:02x}"

    # 1. Check cache
    cache = _load_cache()
    cached_ip = cache.get(hub_id)
    if cached_ip and _is_reachable(cached_ip):
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
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def ssh(host, command, port, user, password):
    """SSH into an Arcus hub. HOST can be an IP address, hostname, or hub ID.

    If COMMAND is given, run it on the hub and exit. Otherwise open an interactive shell.

    \b
    Examples:
      arcushub ssh LWR-2389
      arcushub ssh LWR-2389 killall java
      arcushub ssh 10.0.1.5 cat /tmp/hubAgent.log
    """
    from .ssh import interactive_shell

    host = _resolve_host(host)
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))
    try:
        if command:
            chan = client.get_transport().open_session()
            chan.exec_command(" ".join(command))
            while True:
                data = chan.recv(4096)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            stderr = chan.recv_stderr(4096)
            if stderr:
                sys.stderr.buffer.write(stderr)
                sys.stderr.buffer.flush()
            sys.exit(chan.recv_exit_status())
        else:
            interactive_shell(client)
    finally:
        client.close()



@cli.command("debug-key")
@click.argument("hub_id")
@click.option("--data-dir", type=click.Path(exists=True, path_type=Path), default=_DEFAULT_DATA_DIR, help="Path to hub data directory.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None, help="Output file path (default: ./<HUB_ID>.dbg).")
def debug_key(hub_id, data_dir, output):
    """Extract the debug key file for a hub."""
    from .debug_keys import extract_debug_key

    output_dir = output.parent if output else Path.cwd()
    if output:
        # If user gave a full output path, we extract to its parent and rename
        hub_id_upper = hub_id.upper()
        out = extract_debug_key(hub_id, data_dir, output_dir)
        if out.name != output.name:
            output.parent.mkdir(parents=True, exist_ok=True)
            out.rename(output)
            out = output
    else:
        out = extract_debug_key(hub_id, data_dir, output_dir)

    click.echo(out)


@cli.command("enable-dropbear")
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def enable_dropbear(host, port, user, password):
    """Enable dropbear SSH server on a hub by default. HOST can be an IP, hostname, or hub ID."""
    host = _resolve_host(host)
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        _stdin, stdout, stderr = client.exec_command("touch /data/config/enable_console")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            err = stderr.read().decode().strip()
            raise click.ClickException(f"Failed to enable dropbear: {err}")
        click.echo("Dropbear enabled. It will start on next boot.")
    finally:
        client.close()


@cli.command("setup-ssh-key")
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
@click.option("--key", type=click.Path(exists=True, path_type=Path), default=None, help="Path to SSH public key file (default: auto-detect).")
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

    host = _resolve_host(host)
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        cmd = f"mkdir -p /data/config/dropbear && cat >> /data/config/dropbear/authorized_keys << 'SSHKEY'\n{key_content}\nSSHKEY"
        _stdin, stdout, stderr = client.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            err = stderr.read().decode().strip()
            raise click.ClickException(f"Failed to install SSH key: {err}")
        click.echo("SSH key installed. You can now connect without a password.")
    finally:
        client.close()


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

    import subprocess

    cache = _load_cache()
    rows = []
    with _spinner(f"Pinging {len(found)} hub{'s' if len(found) != 1 else ''}"):
        for ip, mac in found:
            hub_id = mac_to_hub_id(mac)
            cache[hub_id] = ip
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", ip],
                    capture_output=True, timeout=3,
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
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def ping(host, port, user, password):
    """Ping a hub and show basic status. HOST can be an IP, hostname, or hub ID."""
    import subprocess

    host = _resolve_host(host)

    # ICMP ping
    click.echo(f"Pinging {host}...")
    try:
        result = subprocess.run(
            ["ping", "-c", "3", host],
            capture_output=True, text=True, timeout=10,
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

    # Grab uptime and agent status via SSH
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        click.echo(f"  SSH login failed: {e}")
        return

    try:
        _stdin, stdout, _stderr = client.exec_command("uptime")
        uptime = stdout.read().decode().strip()
        if uptime:
            click.echo(f"  Uptime: {uptime}")

        _stdin, stdout, _stderr = client.exec_command("pgrep -f hubAgent")
        agent_pid = stdout.read().decode().strip()
        click.echo(f"  Hub agent: {'running (pid ' + agent_pid.splitlines()[0] + ')' if agent_pid else 'not running'}")
    finally:
        client.close()


@cli.command()
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def reboot(host, port, user, password):
    """Reboot a hub. HOST can be an IP address, hostname, or hub ID."""
    host = _resolve_host(host)
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        client.exec_command("reboot")
        click.echo(f"Reboot command sent to {host}.")
    finally:
        client.close()


@cli.group()
def agent():
    """Hub agent management commands."""


@agent.command()
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def restart(host, port, user, password):
    """Restart the hub agent. HOST can be an IP address, hostname, or hub ID."""
    host = _resolve_host(host)
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        _stdin, stdout, stderr = client.exec_command("/home/root/bin/agent_stop && /home/root/bin/agent_start")
        stdout.channel.recv_exit_status()
        click.echo(f"Agent restarted on {host}.")
    finally:
        client.close()


@agent.command()
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def reinstall(host, port, user, password):
    """Reinstall the hub agent. Deletes /data/agent and reboots to re-extract from tarball.

    Preserves pairing data in /data/iris. HOST can be an IP, hostname, or hub ID.
    """
    host = _resolve_host(host)
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        click.echo("Removing /data/agent and rebooting...")
        client.exec_command("rm -rf /data/agent && reboot")
        click.echo(f"Agent reinstall initiated on {host}.")
    finally:
        client.close()


@agent.command()
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def reset(host, port, user, password):
    """Factory reset the hub agent. Deletes /data/agent AND /data/iris, then reboots.

    WARNING: This wipes all pairing data. HOST can be an IP, hostname, or hub ID.
    """
    if not click.confirm("This will delete all agent data AND pairing data. Continue?"):
        raise SystemExit(0)

    host = _resolve_host(host)
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        click.echo("Removing /data/agent and /data/iris, then rebooting...")
        client.exec_command("rm -rf /data/agent /data/iris && reboot")
        click.echo(f"Agent reset initiated on {host}.")
    finally:
        client.close()


@agent.command()
@click.argument("host")
@click.argument("tarfile", type=click.Path(exists=True, path_type=Path))
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def install(host, tarfile, port, user, password):
    """Install a new agent tarball on a hub. Uploads the tarball, removes /data/agent, and reboots.

    Preserves pairing data in /data/iris. HOST can be an IP, hostname, or hub ID.

    \b
    Examples:
      arcushub agent install LWR-2389 iris-agent-hub.tgz
      arcushub agent install 10.0.1.5 ./build/iris-agent-hub.tar.gz
    """
    host = _resolve_host(host)

    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    tmp_path = "/tmp/iris-agent-hub"

    try:
        prog = _Progress(total=Path(tarfile).stat().st_size)
        with _spinner(f"Uploading {tarfile} → {tmp_path}", progress=prog):
            chan = client.get_transport().open_session()
            chan.exec_command(f"cat > {tmp_path}")
            with open(tarfile, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    chan.sendall(chunk)
                    prog.update(len(chunk))
            chan.shutdown_write()
            chan.recv_exit_status()

        with _spinner("Installing agent and rebooting"):
            chan = client.get_transport().open_session()
            chan.exec_command(f"PATH=/home/root/bin:$PATH agent_install {tmp_path}")
            chan.recv_exit_status()
        click.echo(f"Agent installed on {host}.")
    finally:
        client.close()


@agent.command()
@click.argument("host")
@click.argument("tarfile", type=click.Path(exists=True, path_type=Path))
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def test(host, tarfile, port, user, password):
    """Upload and hot-swap an agent tarball without rebooting.

    Stops the agent, extracts the new tarball over /data/agent, and restarts it.
    Useful for rapid iteration during development.

    \b
    Examples:
      arcushub agent test LWR-2389 iris-agent-hub.tgz
      arcushub agent test 10.0.1.5 ./build/iris-agent-hub.tar.gz
    """
    host = _resolve_host(host)
    tmp_path = "/tmp/iris-agent-hub"

    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        prog = _Progress(total=Path(tarfile).stat().st_size)
        with _spinner(f"Uploading {tarfile} → {tmp_path}", progress=prog):
            chan = client.get_transport().open_session()
            chan.exec_command(f"cat > {tmp_path}")
            with open(tarfile, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    chan.sendall(chunk)
                    prog.update(len(chunk))
            chan.shutdown_write()
            chan.recv_exit_status()

        click.echo("Stopping agent, extracting, and restarting...")
        install_cmd = (
            "killall java; "
            "cd /data/agent && "
            "rm -rf lib bin conf libs && rm -f * && "
            f"tar xf {tmp_path} && "
            "chown -R agent . && chgrp -R agent . && "
            "agent_start"
        )
        chan = client.get_transport().open_session()
        chan.exec_command(install_cmd)
        chan.recv_exit_status()
        click.echo(f"Agent restarted on {host}.")
    finally:
        client.close()


_ARCUSPLATFORM_DIST = Path.home() / "projects" / "arcusplatform" / "agent" / "arcus-agent" / "hub-v2" / "build" / "distributions"


@agent.command()
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
@click.option("--dist", type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to distTar directory (default: ~/projects/arcusplatform/.../distributions).")
@click.option("--all", "upload_all", is_flag=True, help="Upload all jars, not just changed ones.")
def update(host, port, user, password, dist, upload_all):
    """Update changed agent jars on a hub from the local distTar build.

    Compares jar files in the local distTar archive with those on the hub,
    uploads only the ones that differ (by size), and restarts the agent.

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

    # Extract jar info from tarball
    local_jars = {}
    with tarfile_mod.open(tarball, "r:gz") as tf:
        for member in tf.getmembers():
            if member.name.startswith("libs/") and member.name.endswith(".jar"):
                jar_name = member.name[5:]  # strip "libs/"
                local_jars[jar_name] = member.size

    if not local_jars:
        raise click.ClickException("No jars found in tarball.")

    host = _resolve_host(host)
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        # Get jar sizes from hub
        remote_jars = {}
        with _spinner("Reading hub jars"):
            chan = client.get_transport().open_session()
            chan.exec_command("ls -l /data/agent/libs/*.jar 2>/dev/null")
            output = b""
            while True:
                data = chan.recv(65536)
                if not data:
                    break
                output += data
            chan.recv_exit_status()

        for line in output.decode().splitlines():
            parts = line.split()
            if len(parts) >= 9 and parts[-1].endswith(".jar"):
                jar_name = parts[-1].rsplit("/", 1)[-1]
                try:
                    remote_jars[jar_name] = int(parts[4])
                except ValueError:
                    pass

        # Determine which jars need updating
        if upload_all:
            changed = sorted(local_jars.keys())
        else:
            changed = []
            for jar_name, local_size in sorted(local_jars.items()):
                remote_size = remote_jars.get(jar_name)
                if remote_size is None or remote_size != local_size:
                    changed.append(jar_name)

        if not changed:
            click.echo("All jars are up to date.")
            return

        click.echo(f"{len(changed)} jar{'s' if len(changed) != 1 else ''} to update:")
        for jar_name in changed:
            local_size = local_jars[jar_name]
            remote_size = remote_jars.get(jar_name)
            if remote_size is None:
                click.echo(f"  + {jar_name} ({_format_size(local_size)})")
            else:
                click.echo(f"  ~ {jar_name} ({_format_size(remote_size)} → {_format_size(local_size)})")

        # Stop the agent before uploading
        with _spinner("Stopping agent"):
            chan = client.get_transport().open_session()
            chan.exec_command("killall java")
            chan.recv_exit_status()

        # Extract and upload changed jars
        with tarfile_mod.open(tarball, "r:gz") as tf:
            for jar_name in changed:
                member = tf.getmember(f"libs/{jar_name}")
                jar_data = tf.extractfile(member).read()
                remote_path = f"/data/agent/libs/{jar_name}"

                prog = _Progress(total=len(jar_data))
                with _spinner(f"Uploading {jar_name}", progress=prog):
                    chan = client.get_transport().open_session()
                    chan.exec_command(f"cat > {remote_path}")
                    offset = 0
                    while offset < len(jar_data):
                        chunk = jar_data[offset:offset + 65536]
                        chan.sendall(chunk)
                        prog.update(len(chunk))
                        offset += len(chunk)
                    chan.shutdown_write()
                    chan.recv_exit_status()

        # Fix ownership and restart
        with _spinner("Restarting agent"):
            chan = client.get_transport().open_session()
            chan.exec_command(
                "chown agent:agent /data/agent/libs/*.jar && "
                "agent_start"
            )
            chan.recv_exit_status()

        click.echo(f"Updated {len(changed)} jar{'s' if len(changed) != 1 else ''} on {host}.")
    finally:
        client.close()


@agent.command()
@click.argument("host")
@click.argument("key", required=False, default=None)
@click.argument("value", required=False, default=None)
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def config(host, key, value, port, user, password):
    """Get, set, or list hub database config values.

    HOST can be an IP address, hostname, or hub ID.

    \b
    Examples:
      arcushub agent config 10.0.1.5                          # list all keys
      arcushub agent config LWR-2389 iris.gateway.uri         # get value
      arcushub agent config LWR-2389 iris.gateway.uri wss://… # set value
    """
    import shlex

    db_path = "/data/iris/db/iris.db"
    host = _resolve_host(host)

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

    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        chan = client.get_transport().open_session()
        chan.exec_command(cmd)
        output = b""
        while True:
            data = chan.recv(4096)
            if not data:
                break
            output += data
        stderr = chan.recv_stderr(4096)
        exit_code = chan.recv_exit_status()

        if exit_code != 0:
            err_msg = stderr.decode().strip() if stderr else "unknown error"
            raise click.ClickException(f"sqlite3 failed: {err_msg}")

        text = output.decode().strip()
        if value is not None:
            click.echo(f"Set {key}={value}")
        elif text:
            click.echo(text)
        else:
            if key is not None:
                click.echo(f"No config entry for '{key}'.")
    finally:
        client.close()


cli.add_command(agent)


@cli.command()
@click.argument("src")
@click.argument("dst")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
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

    remote_host = src_host or dst_host
    remote_host = _resolve_host(remote_host)

    try:
        client = _connect(remote_host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        if src_host:
            # Download: cat remote file to local
            if Path(dst_path).is_dir():
                dst_path = str(Path(dst_path) / Path(src_path).name)
            prog = _Progress()
            with _spinner(f"Downloading {src_path} → {dst_path}", progress=prog):
                chan = client.get_transport().open_session()
                chan.exec_command(f"cat {src_path}")
                with open(dst_path, "wb") as f:
                    while True:
                        data = chan.recv(65536)
                        if not data:
                            break
                        f.write(data)
                        prog.update(len(data))
                if chan.recv_exit_status() != 0:
                    raise click.ClickException(f"Remote file not found: {src_path}")
        else:
            # Upload: pipe local file into cat on remote
            # If remote path is a directory, append the source filename
            chan = client.get_transport().open_session()
            chan.exec_command(f"test -d {dst_path}")
            if chan.recv_exit_status() == 0:
                dst_path = dst_path.rstrip("/") + "/" + Path(src_path).name

            # Verify remote directory exists before transferring
            remote_dir = dst_path.rsplit("/", 1)[0] if "/" in dst_path else "."
            chan = client.get_transport().open_session()
            chan.exec_command(f"test -d {remote_dir}")
            if chan.recv_exit_status() != 0:
                raise click.ClickException(f"Remote directory does not exist: {remote_dir}")

            total = Path(src_path).stat().st_size
            prog = _Progress(total=total)
            with _spinner(f"Uploading {src_path} → {dst_path}", progress=prog):
                chan = client.get_transport().open_session()
                chan.exec_command(f"cat > {dst_path}")
                with open(src_path, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        chan.sendall(chunk)
                        prog.update(len(chunk))
                chan.shutdown_write()
                chan.recv_exit_status()
    finally:
        client.close()


@cli.command()
@click.argument("host")
@click.argument("firmware", type=click.Path(exists=True, path_type=Path))
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
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
    host = _resolve_host(host)

    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        # Ensure upload directory exists; fall back to /tmp if
        # /data/iris/data/tmp cannot be created (agent may be broken).
        remote_dir = "/data/iris/data/tmp"
        chan = client.get_transport().open_session()
        chan.exec_command(f"mkdir -p {remote_dir} && chown agent:agent {remote_dir} 2>/dev/null && echo ok")
        result = chan.recv(16).decode().strip()
        chan.close()
        if result != "ok":
            remote_dir = "/tmp"
        remote_path = f"{remote_dir}/hubOS.bin"

        # Upload firmware via exec channel (hub SSH lacks SFTP)
        prog = _Progress(total=firmware.stat().st_size)
        with _spinner(f"Uploading {firmware.name} → {remote_path}", progress=prog):
            chan = client.get_transport().open_session()
            chan.exec_command(f"cat > {remote_path}")
            with open(firmware, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    chan.sendall(chunk)
                    prog.update(len(chunk))
            chan.shutdown_write()
            chan.recv_exit_status()

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
        while True:
            data = chan.recv(4096)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        stderr = chan.recv_stderr(4096)
        exit_status = chan.recv_exit_status()
        if exit_status != 0:
            err = stderr.decode().strip() if stderr else f"exit code {exit_status}"
            raise click.ClickException(f"Firmware install failed: {err}")
        if wipe_agent:
            with _spinner("Stopping agent"):
                chan = client.get_transport().open_session()
                chan.exec_command("/home/root/bin/agent_stop")
                chan.recv_exit_status()
            with _spinner("Wiping /data/agent"):
                chan = client.get_transport().open_session()
                chan.exec_command("rm -rf /data/agent")
                chan.recv_exit_status()

        # Clean up uploaded firmware
        chan = client.get_transport().open_session()
        chan.exec_command(f"rm -f {remote_path}")
        chan.recv_exit_status()

        click.echo("Firmware install complete. Rebooting...")
        chan = client.get_transport().open_session()
        chan.exec_command("/sbin/reboot")
        chan.recv_exit_status()
    finally:
        client.close()


@cli.command()
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
@click.option("-f", "--follow", is_flag=True, help="Follow the log in real time (like tail -f).")
@click.option("-n", "--lines", default=50, help="Number of lines to show when following.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None, help="Save log to this file (default: hubAgent.log).")
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
    host = _resolve_host(host)
    try:
        client = _connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        if follow:
            chan = client.get_transport().open_session()
            chan.exec_command(f"tail -n {lines} -f {remote_path}")
            try:
                while True:
                    data = chan.recv(4096)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
            except KeyboardInterrupt:
                pass
        else:
            local_path = output or Path("hubAgent.log")
            prog = _Progress()
            with _spinner(f"Downloading {remote_path} → {local_path}", progress=prog):
                chan = client.get_transport().open_session()
                chan.exec_command(f"cat {remote_path}")
                with open(local_path, "wb") as f:
                    while True:
                        data = chan.recv(65536)
                        if not data:
                            break
                        f.write(data)
                        prog.update(len(data))
                if chan.recv_exit_status() != 0:
                    raise click.ClickException(f"Failed to read {remote_path}")
    finally:
        client.close()

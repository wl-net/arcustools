import sys
from pathlib import Path

import click

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


def _find_in_arp(mac_even: str, mac_odd: str) -> str | None:
    """Search the ARP table for a MAC, return the IP or None."""
    import re
    import subprocess
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
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
    click.echo("Running SSDP discovery...")
    discover(timeout=timeout)

    ip = _find_in_arp(mac_even, mac_odd)
    if ip:
        cache[hub_id] = ip
        _save_cache(cache)
        return ip

    raise click.ClickException(f"Hub {hub_id} not found on the network.")


@cli.command()
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def login(host, port, user, password):
    """SSH into an Arcus hub. HOST can be an IP address, hostname, or hub ID."""
    from .ssh import connect, interactive_shell

    host = _resolve_host(host)
    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    click.echo("Connected.")
    try:
        interactive_shell(client)
    finally:
        client.close()


cli.add_command(login, "ssh")


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
    from .ssh import connect

    host = _resolve_host(host)
    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
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
    from .ssh import connect

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
    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
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
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def reboot(host, port, user, password):
    """Reboot a hub. HOST can be an IP address, hostname, or hub ID."""
    from .ssh import connect

    host = _resolve_host(host)
    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        client.exec_command("reboot")
        click.echo(f"Reboot command sent to {host}.")
    finally:
        client.close()


@cli.command("restart-agent")
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def restart_agent(host, port, user, password):
    """Restart the hub agent. HOST can be an IP address, hostname, or hub ID."""
    from .ssh import connect

    host = _resolve_host(host)
    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        _stdin, stdout, stderr = client.exec_command("/home/root/bin/agent_stop && /home/root/bin/agent_start")
        stdout.channel.recv_exit_status()
        click.echo(f"Agent restarted on {host}.")
    finally:
        client.close()


@cli.command("agent-reinstall")
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def agent_reinstall(host, port, user, password):
    """Reinstall the hub agent. Deletes /data/agent and reboots to re-extract from tarball.

    Preserves pairing data in /data/iris. HOST can be an IP, hostname, or hub ID.
    """
    from .ssh import connect

    host = _resolve_host(host)
    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        click.echo("Removing /data/agent and rebooting...")
        client.exec_command("rm -rf /data/agent && reboot")
        click.echo(f"Agent reinstall initiated on {host}.")
    finally:
        client.close()


@cli.command("agent-reset")
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def agent_reset(host, port, user, password):
    """Factory reset the hub agent. Deletes /data/agent AND /data/iris, then reboots.

    WARNING: This wipes all pairing data. HOST can be an IP, hostname, or hub ID.
    """
    from .ssh import connect

    if not click.confirm("This will delete all agent data AND pairing data. Continue?"):
        raise SystemExit(0)

    host = _resolve_host(host)
    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        click.echo("Removing /data/agent and /data/iris, then rebooting...")
        client.exec_command("rm -rf /data/agent /data/iris && reboot")
        click.echo(f"Agent reset initiated on {host}.")
    finally:
        client.close()


@cli.command("agent-install")
@click.argument("host")
@click.argument("tarfile", type=click.Path(exists=True, path_type=Path))
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
def agent_install(host, tarfile, port, user, password):
    """Install a new agent tarball on a hub. Uploads the tarball, removes /data/agent, and reboots.

    Preserves pairing data in /data/iris. HOST can be an IP, hostname, or hub ID.

    \b
    Examples:
      arcushub agent-install LWR-2389 iris-agent-hub.tgz
      arcushub agent-install 10.0.1.5 ./build/iris-agent-hub.tar.gz
    """
    from .ssh import connect

    host = _resolve_host(host)
    remote_path = "/home/agent/iris-agent-hub"

    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        click.echo(f"Uploading {tarfile} -> {remote_path}...")
        chan = client.get_transport().open_session()
        chan.exec_command(f"cat > {remote_path}")
        with open(tarfile, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                chan.sendall(chunk)
        chan.shutdown_write()
        chan.recv_exit_status()

        click.echo("Removing /data/agent and rebooting...")
        client.exec_command("rm -rf /data/agent && reboot")
        click.echo(f"Agent install initiated on {host}.")
    finally:
        client.close()


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
    from .ssh import connect

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

    remote_host = src_host or dst_host
    remote_host = _resolve_host(remote_host)

    click.echo(f"Connecting to {user}@{remote_host}:{port}...")
    try:
        client = connect(remote_host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        if src_host:
            # Download: cat remote file to local
            click.echo(f"Downloading {src_path} -> {dst_path}")
            chan = client.get_transport().open_session()
            chan.exec_command(f"cat {src_path}")
            with open(dst_path, "wb") as f:
                while True:
                    data = chan.recv(65536)
                    if not data:
                        break
                    f.write(data)
            if chan.recv_exit_status() != 0:
                raise click.ClickException(f"Remote file not found: {src_path}")
        else:
            # Upload: pipe local file into cat on remote
            click.echo(f"Uploading {src_path} -> {dst_path}")
            chan = client.get_transport().open_session()
            chan.exec_command(f"cat > {dst_path}")
            with open(src_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    chan.sendall(chunk)
            chan.shutdown_write()
            chan.recv_exit_status()
        click.echo("Done.")
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
@click.option("-f", "--force", is_flag=True, help="Force install even if version is the same.")
def flash(host, firmware, port, user, password, kill_agent, skip_radio, force):
    """Upload and install firmware on a hub. HOST can be an IP, hostname, or hub ID.

    \b
    Examples:
      arcushub flash LWR-2389 hub/v2/firmware/hubOS_2.2.0.009.bin
      arcushub flash 10.0.1.5 hub/v3/firmware/hubOSv3_3.0.1.025.bin
    """
    from .ssh import connect

    host = _resolve_host(host)
    remote_path = f"/tmp/{firmware.name}"

    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        # Upload firmware via exec channel (hub SSH lacks SFTP)
        click.echo(f"Uploading {firmware.name} -> {remote_path}...")
        chan = client.get_transport().open_session()
        chan.exec_command(f"cat > {remote_path}")
        with open(firmware, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                chan.sendall(chunk)
        chan.shutdown_write()
        chan.recv_exit_status()

        # Decide whether to use fwinstall (local file) or update (URL)
        # Since we uploaded the file, use fwinstall
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
        click.echo("Firmware install complete. Rebooting...")
        chan = client.get_transport().open_session()
        chan.exec_command("reboot")
        chan.recv_exit_status()
    finally:
        client.close()


@cli.command()
@click.argument("host")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="Override password (skip auto-detection).")
@click.option("-n", "--lines", default=50, help="Number of existing lines to show.")
def logs(host, port, user, password, lines):
    """Tail /tmp/hubAgent.log on a hub. HOST can be an IP, hostname, or hub ID."""
    from .ssh import connect

    host = _resolve_host(host)
    click.echo(f"Connecting to {user}@{host}:{port}...")
    try:
        client = connect(host, port=port, user=user, password=password)
    except Exception as e:
        raise click.ClickException(str(e))

    try:
        chan = client.get_transport().open_session()
        chan.exec_command(f"tail -n {lines} -f /tmp/hubAgent.log")
        try:
            while True:
                data = chan.recv(4096)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
        except KeyboardInterrupt:
            pass
    finally:
        client.close()

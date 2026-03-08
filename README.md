# arcustools

Collection of tools for Arcus, mostly stuff that is too large to fit in arcusplatform.

## arcushub CLI

A command-line tool for managing Arcus hubs on a local network.

### Installation

```sh
pipx install -e .
```

Or using a virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Hub identification

Most commands accept a **host** argument that can be an IP address, hostname, or hub ID (e.g. `LWR-2389`). When a hub ID is provided, the tool resolves it to an IP address by:

1. Checking a local cache (`~/.cache/arcushub/hosts.json`) with a quick reachability probe
2. Checking the ARP table
3. Running SSDP/UPnP discovery to find the hub on the network

Hub IDs are derived from the hub's MAC address using a base-23 encoding scheme. The tool knows the Arcus OUI (`00:16:A2`) and can convert in both directions.

### Commands

#### `arcushub ssh <host> [command...]`

SSH into a hub as root. Automatically tries known root passwords for hubOS 2.x, 3.x, and source builds. If a command is given, runs it on the hub and exits. Otherwise opens an interactive shell.

```sh
arcushub ssh LWR-2389
arcushub ssh LWR-2389 killall java
arcushub ssh LWR-2389 cat /tmp/hubAgent.log
```

#### `arcushub find <hub_id>`

Find a hub's IP address on the local network by its hub ID.

```sh
arcushub find LWR-2389
arcushub find LWR-2389 --timeout 10
```

#### `arcushub hubs`

Discover all Arcus hubs on the local network. Runs SSDP discovery to populate the ARP table, then scans for MACs matching known Arcus OUIs and displays each hub's ID, IP, and MAC address.

```sh
arcushub hubs
arcushub hubs --timeout 10
```

#### `arcushub ping <host>`

Ping a hub and show basic status: ICMP latency, SSH port status, uptime, and agent process status.

```sh
arcushub ping LWR-2389
arcushub ping 10.105.1.200
```

#### `arcushub logs <host>`

Download or follow `/tmp/hubAgent.log` on a hub. By default, downloads the full log file. Use `-f` to follow in real time.

```sh
arcushub logs LWR-2389              # download full log
arcushub logs LWR-2389 -o hub.log   # download to specific file
arcushub logs LWR-2389 -f           # follow log in real time
arcushub logs LWR-2389 -f -n 100    # follow, showing last 100 lines
```

#### `arcushub flash <host> <firmware>`

Upload and install firmware on a hub. Automatically detects signed firmware (uses `update`) vs unsigned archives (uses `fwinstall`).

```sh
arcushub flash LWR-2389 hub/v2/firmware/hubOS_2.2.0.009.bin
arcushub flash LWR-2389 hub/v3/firmware/hubOSv3_3.0.1.025.bin -k    # kill agent first
arcushub flash LWR-2389 firmware.bin -s                               # skip radio firmware
arcushub flash LWR-2389 firmware.bin -f                               # force install
```

#### `arcushub reboot <host>`

Reboot a hub.

```sh
arcushub reboot LWR-2389
```

#### `arcushub scp <src> <dst>`

Copy files to or from a hub over SSH using `HOST:PATH` syntax.

```sh
arcushub scp firmware.bin LWR-2389:/tmp/
arcushub scp LWR-2389:/var/log/messages ./messages
```

#### `arcushub debug-key <hub_id>`

Extract the `.dbg` debug key file for a hub from the local ZIP archives in `hub/`.

```sh
arcushub debug-key LWC-8045                    # outputs LWC-8045.dbg to current dir
arcushub debug-key LWC-8045 -o /tmp/key.dbg    # custom output path
```

#### `arcushub enable-dropbear <host>`

Enable the dropbear SSH server to start by default on boot (creates `/data/config/enable_console`).

```sh
arcushub enable-dropbear LWR-2389
```

#### `arcushub setup-ssh-key <host>`

Push your local SSH public key to a hub for passwordless login. Auto-detects `~/.ssh/id_ed25519.pub`, falling back to `~/.ssh/id_rsa.pub`.

```sh
arcushub setup-ssh-key LWR-2389
arcushub setup-ssh-key LWR-2389 --key ~/.ssh/id_rsa.pub
```

### Agent commands

Agent lifecycle commands are grouped under `arcushub agent`.

#### `arcushub agent restart <host>`

Restart the hub agent (runs `agent_stop` then `agent_start`).

```sh
arcushub agent restart LWR-2389
```

#### `arcushub agent install <host> <tarfile>`

Upload and install a new agent tarball on a hub. Removes `/data/agent` and reboots to extract the new tarball. Preserves pairing data in `/data/iris`.

```sh
arcushub agent install LWR-2389 iris-agent-hub.tgz
```

#### `arcushub agent test <host> <tarfile>`

Hot-swap an agent tarball without rebooting. Stops the agent, extracts the new tarball over `/data/agent`, and restarts it. Useful for rapid iteration during development.

```sh
arcushub agent test LWR-2389 iris-agent-hub.tgz
```

#### `arcushub agent reinstall <host>`

Reinstall the hub agent by deleting `/data/agent` and rebooting. The agent tarball is re-extracted on boot. Pairing data in `/data/iris` is preserved.

```sh
arcushub agent reinstall LWR-2389
```

#### `arcushub agent reset <host>`

Factory reset the hub agent. Deletes `/data/agent` **and** `/data/iris` (all pairing data), then reboots.

```sh
arcushub agent reset LWR-2389
```

### Common options

All commands that connect to a hub support:

| Option | Default | Description |
|---|---|---|
| `--port` | 22 | SSH port |
| `--user` | root | SSH username |
| `--password` | *(auto)* | Override password, skip trying known defaults |

# arcustools

Collection of tools for Arcus, mostly stuff that is too large to fit in arcusplatform.

## arcushub CLI

A command-line tool for managing Arcus hubs on a local network.

### Installation

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

#### `arcushub login <host>`

SSH into a hub as root. Automatically tries known root passwords for hubOS 2.x, 3.x, and source builds. Supports legacy `ssh-rsa` host key algorithms for older firmware.

```sh
arcushub login 10.105.1.200
arcushub login LWR-2389
arcushub login LWR-2389 --port 2222
```

#### `arcushub find <hub_id>`

Find a hub's IP address on the local network by its hub ID.

```sh
arcushub find LWR-2389
arcushub find LWR-2389 --timeout 10
```

#### `arcushub debug-key <hub_id>`

Extract the `.dbg` debug key file for a hub from the local ZIP archives in `hub/`.

```sh
arcushub debug-key LWC-8045                    # outputs LWC-8045.dbg to current dir
arcushub debug-key LWC-8045 -o /tmp/key.dbg    # custom output path
```

#### `arcushub logs <host>`

Tail `/tmp/hubAgent.log` on a hub. Press Ctrl-C to stop.

```sh
arcushub logs LWR-2389
arcushub logs 10.105.1.200 -n 100    # show last 100 lines
```

#### `arcushub flash <host> <firmware>`

Upload a firmware binary to a hub and install it using `fwinstall`.

```sh
arcushub flash LWR-2389 hub/v2/firmware/hubOS_2.2.0.009.bin
arcushub flash LWR-2389 hub/v3/firmware/hubOSv3_3.0.1.025.bin -k    # kill agent first
arcushub flash LWR-2389 firmware.bin -s                               # skip radio firmware
```

#### `arcushub reboot <host>`

Reboot a hub.

```sh
arcushub reboot LWR-2389
```

#### `arcushub restart-agent <host>`

Restart the hub agent (runs `agent_stop` then `agent_start`).

```sh
arcushub restart-agent LWR-2389
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

#### `arcushub agent-reinstall <host>`

Reinstall the hub agent by deleting `/data/agent` and rebooting. The agent tarball is re-extracted on boot. Pairing data in `/data/iris` is preserved.

```sh
arcushub agent-reinstall LWR-2389
```

#### `arcushub agent-reset <host>`

Factory reset the hub agent. Deletes `/data/agent` **and** `/data/iris` (all pairing data), then reboots.

```sh
arcushub agent-reset LWR-2389
```

#### `arcushub agent-install <host> <tarfile>`

Upload and install a new agent tarball on a hub. Removes `/data/agent` and reboots to extract the new tarball.

```sh
arcushub agent-install LWR-2389 iris-agent-hub.tgz
```

#### `arcushub scp <src> <dst>`

Copy files to or from a hub over SSH using `HOST:PATH` syntax.

```sh
arcushub scp firmware.bin LWR-2389:/tmp/
arcushub scp LWR-2389:/var/log/messages ./messages
```

### Common options

All commands that connect to a hub support:

| Option | Default | Description |
|---|---|---|
| `--port` | 22 | SSH port |
| `--user` | root | SSH username |
| `--password` | *(auto)* | Override password, skip trying known defaults |

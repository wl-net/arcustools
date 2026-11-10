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
2. Checking the ARP table, and that the entry is still current
3. Running SSDP/UPnP discovery to find the hub on the network
4. Asking the hubs that answered discovery for their MAC over SSH, falling back on the UUID a hub announces if it was seen before and SSH can't settle it

On macOS 27, Homebrew python (and so a default pipx install) gets an empty ARP table with no error. A hub then has to be identified over SSH once, after which step 4 recognises it even if SSH is closed or its IP changes. Known UUIDs are kept in `~/.cache/arcushub/hub_uuids.json`.

`find`, `hubs` and `ping` take `--port`, `--user` and `--password` for those SSH checks.

Hub IDs are derived from the hub's MAC address using a base-23 encoding scheme. The tool knows the Arcus OUI (`00:16:A2`) and can convert in both directions.

### Commands

#### `arcushub ssh <host> [command...]`

SSH into a hub as root. Tries your local SSH keys first (see `setup-ssh-key`), then the known root passwords for hubOS 2.x, 3.x, and source builds. If a command is given, runs it on the hub and exits. Otherwise opens an interactive shell.

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

Download or follow `/tmp/hubAgent.log` on a hub. By default, downloads the full log file. Use `-f` to follow in real time, or `-o -` to print the log to stdout.

When the agent exits, its supervisor moves the log to `/tmp/hubAgent.last` and starts a new agent. `--previous` reads that file, so you can see what led up to an agent crash or restart. The next restart replaces it, and a reboot clears both logs, since `/tmp` is in RAM.

```sh
arcushub logs LWR-2389                         # download full log
arcushub logs LWR-2389 -o hub.log              # download to specific file
arcushub logs LWR-2389 -o - | grep -i zwave    # print the log to stdout
arcushub logs LWR-2389 --previous              # download the log from before the last restart
arcushub logs LWR-2389 -f                      # follow log in real time
arcushub logs LWR-2389 -f -n 100               # follow, showing last 100 lines
```

#### `arcushub flash <host> <firmware>`

Upload and install firmware on a hub, then reboot it. Automatically detects signed firmware (uses `update`) vs unsigned archives (uses `fwinstall`).

The agent is always stopped before installing: the hub stages the decrypted image in `/tmp` (RAM), and with the agent running a large image can exhaust memory and reboot the hub mid-install. Install progress streams live; the install takes several minutes and should not be interrupted.

```sh
arcushub flash LWR-2389 hub/v2/firmware/hubOS_2.2.0.009.bin
arcushub flash LWR-2389 hub/v3/firmware/hubOSv3_3.0.1.025.bin -k    # pass -k (kill agent) to update/fwinstall
arcushub flash LWR-2389 firmware.bin -s                               # skip radio firmware (unsigned archives only)
arcushub flash LWR-2389 firmware.bin -w                               # also wipe /data/agent after installing
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
arcushub debug-key LWC-8045 --data-dir /path/to/hub   # use archives from another directory
```

#### `arcushub enable-dropbear <host>`

Enable the dropbear SSH server to start by default on boot (creates `/data/config/enable_console`).

```sh
arcushub enable-dropbear LWR-2389
```

#### `arcushub setup-ssh-key <host>`

Push your local SSH public key to a hub for passwordless login, then check the matching private key can log in. It works straight away, with no reboot. Auto-detects `~/.ssh/id_ed25519.pub`, falling back to `~/.ssh/id_rsa.pub`. A key given with `--key` is remembered in `~/.cache/arcushub/ssh_keys.json` and offered on later logins.

arcushub doesn't use the SSH agent, so the private key has to be an unencrypted file. A key that can't log in is taken back off the hub, because a hub with SSH enabled and any key installed goes key-only and stops accepting passwords.

```sh
arcushub setup-ssh-key LWR-2389
arcushub setup-ssh-key LWR-2389 --key ~/.ssh/id_rsa.pub
```

### Agent commands

Agent lifecycle commands are grouped under `arcushub agent`.

#### `arcushub agent restart <host>`

Restart the hub agent with `killall java`, leaving `irisagentd` to start it again, as the hub does itself. If `irisagentd` isn't running, starts it through `/etc/init.d/irisagent`. Waits for a new agent to be running.

```sh
arcushub agent restart LWR-2389
```

#### `arcushub agent push <host> <jar...>`

Install locally built jars on a hub and restart the agent. This is the command to use after building a single module.

Uploads to a staging directory while the agent keeps running and checks each jar's MD5, so a failed push changes nothing. Then swaps the jars in, removes the stale `agent.jsa` and restarts the agent. Any other version of the same jar is replaced too, because every file in `libs` goes on the classpath. Replaced jars are kept in `/data/agent/libs.old`, and pushing a jar the hub already has does nothing.

`--dry-run` shows what would change without changing it, `--no-restart` leaves the new jars for the next restart, and `--replace <jar>` names a jar to replace when it has a different name.

```sh
arcushub agent push LWR-2389 build/libs/arcus-zigbee-controller-2.13.29-SNAPSHOT.jar
arcushub agent push LWR-2389 zigbee.jar zwave.jar --dry-run
arcushub agent push LWR-2389 new.jar --replace old-2.13.25.jar --no-restart
```

#### `arcushub agent update <host>`

Update changed agent jars from a local arcusplatform `distTar` build. Compares jars by MD5, uploads the ones that differ to a staging directory while the agent keeps running, then swaps them in and restarts the agent. A failed upload changes nothing, but `/data` needs room for both copies. Use `--all` to upload every jar, or `--dist` to point at a different distributions directory (default: `~/projects/arcusplatform/.../distributions`).

```sh
arcushub agent update LWR-2389
arcushub agent update LWR-2389 --all
arcushub agent update LWR-2389 --dist /path/to/distributions
```

#### `arcushub agent config <host> [key] [value]`

Get, set, or list hub database config values. With no key, lists all keys; with a key, prints its value; with a key and value, sets it.

```sh
arcushub agent config LWR-2389                            # list all keys
arcushub agent config LWR-2389 iris.gateway.uri           # get value
arcushub agent config LWR-2389 iris.gateway.uri wss://…   # set value
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

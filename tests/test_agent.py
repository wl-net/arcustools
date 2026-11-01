"""Tests for putting jars on a hub and restarting its agent.

The hub's real behaviour is what matters here, and it isn't obvious. irisagentd
supervises the agent and starts a new one the moment `killall java` lands. agent_stop
kills the supervisor too, and what agent_start brings up doesn't outlive the SSH
session. Every file in libs goes on the classpath. So these run the real commands in
a shell against a fake hub that behaves that way, rather than matching command strings.
"""

import hashlib
import os
import re
import stat
import subprocess
import sys
import tarfile

import pytest
from click.testing import CliRunner
from conftest import FakeChannel, FakeClient

from arcushub import cli as cli_mod
from arcushub.cli import cli

STUBS = {
    "shim/killall": """#!/bin/sh
echo "killall $*" >> "$HUB/log"
ls "$HUB/data/agent/libs" > "$HUB/libs_at_kill"
cat "$HUB"/data/agent/libs/* > "$HUB/jars_at_kill"
[ -e "$HUB/java_ignores_signals" ] && exit 0
if [ -e "$HUB/supervisor" ] && [ ! -e "$HUB/no_respawn" ]; then
    echo $(($(cat "$HUB/java_pid") + 1)) > "$HUB/java_pid"
else
    : > "$HUB/java_pid"
fi
""",
    "shim/pidof": """#!/bin/sh
case "$1" in
    java) [ -s "$HUB/java_pid" ] && cat "$HUB/java_pid" ;;
    irisagentd) [ -e "$HUB/supervisor" ] ;;
esac
""",
    "shim/chown": """#!/bin/sh
echo "chown $*" >> "$HUB/log"
[ ! -e "$HUB/chown_fails" ]
""",
    "shim/chgrp": "#!/bin/sh\n",
    "shim/fwinstall": """#!/bin/sh
echo "fwinstall $*" >> "$HUB/log"
""",
    "shim/md5sum": f"""#!{sys.executable}
import hashlib, os, sys
for path in sys.argv[1:]:
    if os.path.exists(path):
        digest = hashlib.md5(open(path, "rb").read()).hexdigest()
        if os.path.exists(os.path.join(os.environ["HUB"], "corrupt")) and ".new/" in path:
            digest = "0" * 32
        print(digest + "  " + path)
""",
    "home/root/bin/agent_stop": """#!/bin/sh
echo agent_stop >> "$HUB/log"
rm -f "$HUB/supervisor"
: > "$HUB/java_pid"
""",
    "home/root/bin/agent_start": """#!/bin/sh
echo agent_start >> "$HUB/log"
""",
    "etc/init.d/irisagent": """#!/bin/sh
echo init_script >> "$HUB/log"
touch "$HUB/supervisor"
echo 2000 > "$HUB/java_pid"
""",
}


class HubChannel(FakeChannel):
    def __init__(self, hub, truncate_after=None):
        super().__init__(truncate_after)
        self._hub = hub

    def get_pty(self):
        pass

    def close(self):
        pass

    def exec_command(self, cmd):
        self._hub.commands.append(cmd)
        if "/dev/watchdog0" in cmd:
            cmd = "true"
        self._proc = subprocess.Popen(["sh", "-c", self._hub.local(cmd)], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self._hub.env)


class Hub(FakeClient):
    """A hub in a temp directory, whose commands really run with its paths remapped."""

    def __init__(self, root):
        super().__init__()
        self.root = root
        self.commands = []
        self.env = {**os.environ, "HUB": str(root), "PATH": f"{root}/shim:{os.environ['PATH']}"}
        self.libs = root / "data" / "agent" / "libs"
        self.libs.mkdir(parents=True)
        (root / "tmp").mkdir()
        (root / "var" / "run").mkdir(parents=True)
        (root / "supervisor").touch()
        (root / "java_pid").write_text("1000\n")
        (root / "log").touch()
        (root / "data" / "agent" / "agent.jsa").write_text("archive of the old jars")
        for name, body in STUBS.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def local(self, cmd):
        return re.sub(r"(?<![\w/.:])/(data|home|tmp|etc|var)/", lambda m: f"{self.root}{m.group(0)}", cmd)

    def open_session(self):
        chan = HubChannel(self, self._truncate_after)
        self._truncate_after = None
        return chan

    def exec_command(self, cmd):
        self.commands.append(cmd)  # only flash's reboot comes this way

    @property
    def log(self):
        return (self.root / "log").read_text().splitlines()

    @property
    def java_pid(self):
        return (self.root / "java_pid").read_text().strip()

    @property
    def staging(self):
        return self.root / "data" / "agent" / "libs.new"

    @property
    def backup(self):
        return self.root / "data" / "agent" / "libs.old"

    @property
    def jsa(self):
        return self.root / "data" / "agent" / "agent.jsa"

    @property
    def auth_keys(self):
        return self.root / "data" / "config" / "dropbear" / "authorized_keys"

    @property
    def live_keys(self):
        return self.root / "var" / "run" / "authorized_keys"

    def jars(self):
        return {path.name: path.read_bytes() for path in self.libs.iterdir()}

    def changed_anything(self):
        """Any command beyond the read-only ones that look at the hub."""
        return [cmd for cmd in self.commands if not cmd.startswith(("md5sum", "pidof"))]


@pytest.fixture
def hub(monkeypatch, tmp_path):
    hub = Hub(tmp_path / "hub")
    monkeypatch.setattr(cli_mod, "_resolve_host", lambda host, **kwargs: host)
    monkeypatch.setattr(cli_mod, "_connect", lambda *a, **kw: hub)
    monkeypatch.setattr(cli_mod, "_AGENT_RESTART_TIMEOUT", 0.2)
    monkeypatch.setattr(cli_mod.time, "sleep", lambda seconds: None)
    return hub


@pytest.fixture
def jar(tmp_path):
    def make(name, content=b"new build"):
        path = tmp_path / "build" / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(content)
        return str(path)
    return make


def invoke(*args):
    return CliRunner().invoke(cli, ["agent", *args])


def fail_on_upload(monkeypatch, number):
    real, calls = cli_mod._upload, []

    def upload(*args):
        calls.append(args)
        if len(calls) == number:
            raise cli_mod.click.ClickException("Upload failed: no space left on device")
        real(*args)

    monkeypatch.setattr(cli_mod, "_upload", upload)


def test_push_swaps_the_jar_in_before_restarting(hub, jar):
    (hub.libs / "zigbee-1.0.jar").write_bytes(b"old build")

    result = invoke("push", "hub", jar("zigbee-1.0.jar"))
    assert result.exit_code == 0, result.output
    assert hub.jars() == {"zigbee-1.0.jar": b"new build"}
    # irisagentd starts the next agent as soon as this one dies, so the swap comes first
    assert "killall java" in hub.log
    assert (hub.root / "jars_at_kill").read_bytes() == b"new build"


def test_push_leaves_the_supervisor_running(hub, jar):
    assert invoke("push", "hub", jar("zigbee-1.0.jar")).exit_code == 0
    assert hub.java_pid == "1001"
    assert "agent_stop" not in hub.log and "agent_start" not in hub.log
    assert "init_script" not in hub.log  # it's running, so nothing to start


def test_push_clears_the_shared_class_archive_and_staging(hub, jar):
    assert invoke("push", "hub", jar("zigbee-1.0.jar")).exit_code == 0
    assert not hub.jsa.exists()
    assert not hub.staging.exists()
    assert "chown agent:agent" in " ".join(hub.commands)


def test_push_never_puts_anything_but_jars_in_libs_while_uploading(hub, jar, monkeypatch):
    # The launch script puts every file in libs on the classpath
    real = cli_mod._upload

    def upload(client, f, size, path, label):
        assert path.startswith("/data/agent/libs.new/")
        real(client, f, size, path, label)

    monkeypatch.setattr(cli_mod, "_upload", upload)
    assert invoke("push", "hub", jar("zigbee-1.0.jar")).exit_code == 0


def test_push_keeps_the_jar_it_overwrites(hub, jar):
    (hub.libs / "zigbee-1.0.jar").write_bytes(b"old build")

    assert invoke("push", "hub", jar("zigbee-1.0.jar")).exit_code == 0
    assert (hub.backup / "zigbee-1.0.jar").read_bytes() == b"old build"


@pytest.mark.parametrize("old", ["zigbee-1.0.jar", "zigbee-2.13.27-SNAPSHOT.jar", "zigbee-3.jar"])
def test_push_replaces_another_version_of_the_same_jar(hub, jar, old):
    # Both versions would otherwise go on the classpath
    (hub.libs / old).write_bytes(b"old build")

    result = invoke("push", "hub", jar("zigbee-2.13.29-SNAPSHOT.jar"))
    assert result.exit_code == 0, result.output
    assert hub.jars() == {"zigbee-2.13.29-SNAPSHOT.jar": b"new build"}
    assert (hub.backup / old).read_bytes() == b"old build"


@pytest.mark.parametrize("bystander, pushed", [
    ("zigbee-bridge-1.0.jar", "zigbee-2.0.jar"),
    ("log4j-1.2-api-2.17.jar", "log4j-1.2.17.jar"),
    ("zigbee.jar", "zigbee-2.0.jar"),
])
def test_push_leaves_jars_that_only_look_similar(hub, jar, bystander, pushed):
    (hub.libs / bystander).write_bytes(b"unrelated")

    assert invoke("push", "hub", jar(pushed)).exit_code == 0
    assert hub.jars() == {bystander: b"unrelated", pushed: b"new build"}


def test_push_replaces_a_differently_named_jar_when_told_to(hub, jar):
    # The iris2 controller to the open one: the pattern this command replaces
    (hub.libs / "iris2-zigbee-controller-2.13.25-SNAPSHOT.jar").write_bytes(b"iris2")
    new = "arcus-zigbee-controller-2.13.29-SNAPSHOT.jar"

    result = invoke("push", "hub", jar(new), "--replace", "iris2-zigbee-controller-2.13.25-SNAPSHOT.jar")
    assert result.exit_code == 0, result.output
    assert hub.jars() == {new: b"new build"}
    assert (hub.backup / "iris2-zigbee-controller-2.13.25-SNAPSHOT.jar").read_bytes() == b"iris2"


def test_replacing_a_jar_with_one_of_the_same_name_keeps_the_new_one(hub, jar):
    (hub.libs / "zigbee-1.0.jar").write_bytes(b"old build")

    assert invoke("push", "hub", jar("zigbee-1.0.jar"), "--replace", "zigbee-1.0.jar").exit_code == 0
    assert hub.jars() == {"zigbee-1.0.jar": b"new build"}


def test_push_refuses_to_replace_a_jar_that_is_not_there(hub, jar):
    result = invoke("push", "hub", jar("zigbee-1.0.jar"), "--replace", "typo.jar")
    assert result.exit_code == 1
    assert "typo.jar" in result.output
    assert hub.changed_anything() == []


def test_push_asks_which_jar_when_several_could_be_replaced(hub, jar):
    (hub.libs / "netty-3.10.jar").write_bytes(b"three")
    (hub.libs / "netty-4.1.jar").write_bytes(b"four")

    result = invoke("push", "hub", jar("netty-4.2.jar"))
    assert result.exit_code == 1
    assert "--replace" in result.output
    assert hub.changed_anything() == []


def test_replace_settles_which_jar_when_several_could_be(hub, jar):
    (hub.libs / "netty-3.10.jar").write_bytes(b"three")
    (hub.libs / "netty-4.1.jar").write_bytes(b"four")

    assert invoke("push", "hub", jar("netty-4.2.jar"), "--replace", "netty-4.1.jar").exit_code == 0
    assert set(hub.jars()) == {"netty-3.10.jar", "netty-4.2.jar"}


def test_push_takes_several_jars_at_once(hub, jar):
    assert invoke("push", "hub", jar("zigbee-1.0.jar"), jar("zwave-1.0.jar", b"zw")).exit_code == 0
    assert hub.jars() == {"zigbee-1.0.jar": b"new build", "zwave-1.0.jar": b"zw"}
    assert hub.log.count("killall java") == 1


def test_push_dry_run_shows_the_plan_and_changes_nothing(hub, jar):
    (hub.libs / "zigbee-1.0.jar").write_bytes(b"old build")

    result = invoke("push", "hub", jar("zigbee-2.0.jar"), "--dry-run")
    assert result.exit_code == 0
    assert "+ zigbee-2.0.jar" in result.output and "- zigbee-1.0.jar" in result.output
    assert hashlib.md5(b"new build").hexdigest()[:8] in result.output
    assert hub.changed_anything() == []
    assert hub.jars() == {"zigbee-1.0.jar": b"old build"}


def test_push_no_restart_leaves_the_jars_for_the_next_restart(hub, jar):
    result = invoke("push", "hub", jar("zigbee-1.0.jar"), "--no-restart")
    assert result.exit_code == 0
    assert hub.jars() == {"zigbee-1.0.jar": b"new build"}
    assert hub.java_pid == "1000"
    assert "killall java" not in hub.log
    assert not hub.jsa.exists()  # the next start must not trust it either


def test_pushing_what_the_hub_already_has_does_not_bounce_the_agent(hub, jar):
    # Restarting takes both radios down, so a repeated push shouldn't
    (hub.libs / "zigbee-1.0.jar").write_bytes(b"new build")

    result = invoke("push", "hub", jar("zigbee-1.0.jar"))
    assert result.exit_code == 0
    assert "already on the hub" in result.output
    assert hub.changed_anything() == []


def test_push_clears_out_an_old_version_when_the_jar_itself_is_current(hub, jar):
    (hub.libs / "zigbee-2.0.jar").write_bytes(b"new build")
    (hub.libs / "zigbee-1.0.jar").write_bytes(b"old build")

    result = invoke("push", "hub", jar("zigbee-2.0.jar"))
    assert result.exit_code == 0, result.output
    assert hub.jars() == {"zigbee-2.0.jar": b"new build"}
    assert (hub.backup / "zigbee-1.0.jar").read_bytes() == b"old build"


def test_failed_upload_leaves_the_hub_as_it_was(hub, jar, monkeypatch):
    (hub.libs / "zigbee-1.0.jar").write_bytes(b"old build")
    fail_on_upload(monkeypatch, 2)

    result = invoke("push", "hub", jar("zigbee-1.0.jar"), jar("zwave-1.0.jar", b"zw"))
    assert result.exit_code == 1
    assert "no space left" in result.output
    assert hub.jars() == {"zigbee-1.0.jar": b"old build"}
    assert hub.java_pid == "1000"
    assert hub.jsa.exists()
    assert not hub.staging.exists()


def test_jar_corrupted_on_the_way_up_is_not_installed(hub, jar):
    (hub.libs / "zigbee-1.0.jar").write_bytes(b"old build")
    (hub.root / "corrupt").touch()

    result = invoke("push", "hub", jar("zigbee-1.0.jar"))
    assert result.exit_code == 1
    assert "arrived corrupted" in result.output
    assert hub.jars() == {"zigbee-1.0.jar": b"old build"}
    assert hub.java_pid == "1000"


def test_push_reports_an_agent_that_does_not_come_back(hub, jar):
    (hub.root / "no_respawn").touch()

    result = invoke("push", "hub", jar("zigbee-1.0.jar"))
    assert result.exit_code == 1
    assert "No new agent" in result.output


def test_restart_is_not_fooled_by_the_old_agent_still_running(hub):
    (hub.root / "java_ignores_signals").touch()

    result = invoke("restart", "hub")
    assert result.exit_code == 1
    assert "No new agent" in result.output


def test_restart_lets_the_supervisor_do_it(hub):
    result = invoke("restart", "hub")
    assert result.exit_code == 0, result.output
    assert hub.java_pid == "1001"
    assert hub.log == ["killall java"]  # not agent_stop, which would kill the supervisor


def test_restart_brings_back_a_missing_supervisor_through_the_init_script(hub):
    # After agent_stop. agent_start's supervisor wouldn't outlive this SSH session,
    # and only the init script sets the JVM's memory limits.
    (hub.root / "supervisor").unlink()
    (hub.root / "java_pid").write_text("")

    result = invoke("restart", "hub")
    assert result.exit_code == 0, result.output
    assert hub.log == ["killall java", "init_script"]
    assert hub.java_pid == "2000"


def test_restart_stands_up_to_an_agent_that_is_already_down(hub):
    (hub.root / "java_pid").write_text("")
    (hub.root / "no_respawn").touch()

    result = invoke("restart", "hub")
    assert result.exit_code == 1
    assert "No new agent" in result.output


def make_dist(tmp_path, jars):
    dist = tmp_path / "dist"
    dist.mkdir()
    libs = tmp_path / "tar" / "libs"
    libs.mkdir(parents=True)
    with tarfile.open(dist / "agent.tar.gz", "w:gz") as tar:
        for name, content in jars.items():
            (libs / name).write_bytes(content)
            tar.add(libs / name, arcname=f"libs/{name}")
    return str(dist)


def test_update_swaps_the_changed_jars_in_before_restarting(hub, tmp_path):
    (hub.libs / "a-1.0.jar").write_bytes(b"old a")
    (hub.libs / "b-1.0.jar").write_bytes(b"same b")
    dist = make_dist(tmp_path, {"a-1.0.jar": b"new a", "b-1.0.jar": b"same b"})

    result = invoke("update", "hub", "--dist", dist)
    assert result.exit_code == 0, result.output
    assert hub.jars() == {"a-1.0.jar": b"new a", "b-1.0.jar": b"same b"}
    assert (hub.root / "jars_at_kill").read_bytes() == b"new asame b"  # swapped before the kill
    assert hub.java_pid == "1001"
    assert not hub.jsa.exists()
    assert "agent_start" not in hub.log and "agent_stop" not in hub.log
    assert not hub.backup.exists()  # it can all be rebuilt from the tarball


def test_update_failed_upload_leaves_the_hub_as_it_was(hub, tmp_path, monkeypatch):
    (hub.libs / "a-1.0.jar").write_bytes(b"old a")
    dist = make_dist(tmp_path, {"a-1.0.jar": b"new a", "b-1.0.jar": b"new b"})
    fail_on_upload(monkeypatch, 2)

    assert invoke("update", "hub", "--dist", dist).exit_code == 1
    assert hub.jars() == {"a-1.0.jar": b"old a"}
    assert hub.java_pid == "1000"
    assert not hub.staging.exists()


def test_update_removes_what_an_older_build_left_behind(hub, tmp_path):
    (hub.libs / "a-1.0.jar").write_bytes(b"old a")
    dist = make_dist(tmp_path, {"a-2.0.jar": b"new a"})

    assert invoke("update", "hub", "--dist", dist).exit_code == 0
    assert hub.jars() == {"a-2.0.jar": b"new a"}


def test_update_keeps_two_versions_the_tarball_ships_on_purpose(hub, tmp_path):
    (hub.libs / "netty-3.10.jar").write_bytes(b"three")
    (hub.libs / "netty-4.1.jar").write_bytes(b"old four")
    dist = make_dist(tmp_path, {"netty-3.10.jar": b"three", "netty-4.1.jar": b"new four"})

    assert invoke("update", "hub", "--dist", dist).exit_code == 0
    assert hub.jars() == {"netty-3.10.jar": b"three", "netty-4.1.jar": b"new four"}


def test_agent_test_takes_the_supervisor_down_while_it_extracts(hub, tmp_path):
    # Left running, it would start the agent from a half-extracted directory
    tarball = tmp_path / "agent.tgz"
    (tmp_path / "libs").mkdir()
    (tmp_path / "libs" / "a-1.0.jar").write_bytes(b"new a")
    with tarfile.open(tarball, "w") as tar:
        tar.add(tmp_path / "libs", arcname="libs")

    result = invoke("test", "hub", str(tarball))
    assert result.exit_code == 0, result.output
    assert hub.log[0] == "agent_stop" and hub.log[-1] == "init_script"
    assert "agent_start" not in hub.log
    assert hub.jars() == {"a-1.0.jar": b"new a"}


@pytest.fixture
def key_setup(hub, tmp_path, monkeypatch):
    """A public key to install, with key logins accepted unless a test says otherwise."""
    remembered, logins = [], []
    works = [True]

    def key_login_works(host, port, user, key_file):
        logins.append(key_file)
        return works[0]

    monkeypatch.setattr("arcushub.ssh.key_login_works", key_login_works)
    monkeypatch.setattr("arcushub.ssh.remember_key", remembered.append)
    public_key = tmp_path / "hub_key.pub"
    public_key.write_text("ssh-ed25519 AAAA test\n")
    return public_key, remembered, logins, works


def test_setup_ssh_key_proves_the_key_logs_in_and_remembers_it(key_setup):
    public_key, remembered, logins, _ = key_setup

    result = CliRunner().invoke(cli, ["setup-ssh-key", "hub", "--key", str(public_key)])
    assert result.exit_code == 0, result.output
    assert "without a password" in result.output
    assert logins == [public_key.with_suffix("").resolve()]
    assert remembered == logins


def test_setup_ssh_key_publishes_the_key_to_the_copy_logins_read(key_setup, hub):
    # dropbear reads /var/run/authorized_keys, which the hub only makes at boot, so
    # without this the key wouldn't work, and the login check would fail, until a reboot
    public_key, _, _, _ = key_setup

    assert CliRunner().invoke(cli, ["setup-ssh-key", "hub", "--key", str(public_key)]).exit_code == 0
    assert hub.live_keys.read_text() == "ssh-ed25519 AAAA test\n"
    assert stat.S_IMODE(hub.live_keys.stat().st_mode) == 0o600


def test_setup_ssh_key_does_not_claim_success_for_a_key_that_cannot_log_in(key_setup):
    public_key, remembered, _, works = key_setup
    works[0] = False

    result = CliRunner().invoke(cli, ["setup-ssh-key", "hub", "--key", str(public_key)])
    assert result.exit_code == 1
    assert "without a password" not in result.output
    assert "doesn't use the SSH agent" in result.output
    assert remembered == []


def test_setup_ssh_key_takes_back_a_key_that_cannot_log_in(key_setup, hub):
    # Left there, it would put the hub in key-only mode with a key we can't use
    public_key, _, _, works = key_setup
    works[0] = False
    hub.auth_keys.parent.mkdir(parents=True)
    hub.auth_keys.write_text("ssh-ed25519 ZZZZ someone-elses\n")

    result = CliRunner().invoke(cli, ["setup-ssh-key", "hub", "--key", str(public_key)])
    assert result.exit_code == 1
    assert "taken back off the hub" in result.output
    assert hub.auth_keys.read_text() == "ssh-ed25519 ZZZZ someone-elses\n"
    assert hub.live_keys.read_text() == "ssh-ed25519 ZZZZ someone-elses\n"


def test_setup_ssh_key_leaves_an_empty_key_file_after_taking_back_the_only_key(key_setup, hub):
    # Empty is what keeps irisinitd out of key-only mode, and grep -v exits 1 on it
    public_key, _, _, works = key_setup
    works[0] = False

    assert CliRunner().invoke(cli, ["setup-ssh-key", "hub", "--key", str(public_key)]).exit_code == 1
    assert hub.auth_keys.read_text() == ""
    assert hub.live_keys.read_text() == ""


def test_setup_ssh_key_leaves_a_key_it_did_not_add(key_setup, hub):
    public_key, _, _, works = key_setup
    works[0] = False
    hub.auth_keys.parent.mkdir(parents=True)
    hub.auth_keys.write_text("ssh-ed25519 AAAA test\n")

    result = CliRunner().invoke(cli, ["setup-ssh-key", "hub", "--key", str(public_key)])
    assert result.exit_code == 1
    assert "taken back" not in result.output
    assert hub.auth_keys.read_text() == "ssh-ed25519 AAAA test\n"


def test_setup_ssh_key_needs_no_memory_for_an_auto_detected_key(key_setup, monkeypatch):
    public_key, remembered, _, _ = key_setup
    ssh_dir = public_key.parent / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 BBBB test\n")
    monkeypatch.setattr(cli_mod.Path, "home", lambda: public_key.parent)

    result = CliRunner().invoke(cli, ["setup-ssh-key", "hub"])
    assert result.exit_code == 0, result.output
    assert remembered == []


def test_setup_ssh_key_run_twice_adds_the_key_once(key_setup, hub):
    public_key, _, _, _ = key_setup

    args = ["setup-ssh-key", "hub", "--key", str(public_key)]
    assert CliRunner().invoke(cli, args).exit_code == 0
    assert "already installed" in CliRunner().invoke(cli, args).output
    assert hub.auth_keys.read_text() == "ssh-ed25519 AAAA test\n"


def run_flash(hub, tmp_path):
    firmware = tmp_path / "hubOS.bin"
    firmware.write_bytes(b"\x1f\x8b firmware")
    result = CliRunner().invoke(cli, ["flash", "hub", str(firmware)])
    assert result.exit_code == 0, result.output
    stop = hub.commands.index("/home/root/bin/agent_stop")
    upload = next(i for i, cmd in enumerate(hub.commands) if cmd.startswith("cat > "))
    feeder = next(i for i, cmd in enumerate(hub.commands) if "/dev/watchdog0" in cmd)
    return stop, upload, feeder


def test_flash_keeps_the_agent_running_through_a_normal_upload(hub, tmp_path):
    stop, upload, feeder = run_flash(hub, tmp_path)
    assert upload < stop < feeder


def test_flash_falling_back_to_tmp_stops_the_agent_first(hub, tmp_path):
    # /tmp is RAM, so the image can't sit there alongside the JVM. The watchdog
    # needs feeding from the moment the agent stops, not only once the upload ends.
    (hub.root / "chown_fails").touch()
    stop, upload, feeder = run_flash(hub, tmp_path)
    assert stop < feeder < upload
    assert hub.commands.count("/home/root/bin/agent_stop") == 1

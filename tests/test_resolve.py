"""Tests for hub ID -> IP resolution.

The regressions worth guarding here are the ones that leave `arcushub ssh
<HUB_ID>` dead in the water: an ARP table that is empty rather than merely
missing the hub (macOS withholds it from ad-hoc-signed interpreters), and a
cached IP that DHCP has since handed to a different hub.
"""

import json

import click
import pytest

from arcushub import cli as cli_mod

HUB_ID, HUB_MAC, HUB_IP = "HFH-7156", "a0:19:b2:b0:23:08", "172.16.1.42"
OTHER_ID, OTHER_MAC, OTHER_IP = "LWR-3666", "00:16:a2:04:8b:64", "172.16.1.57"
STALE_IP = "172.16.1.41"

HUB_UUID = "e50c2900-3444-11e8-9cd5-95d30416fa4d"
OTHER_UUID = "7a6d5580-0ec5-11e5-a465-4f1fd9741a32"

IRIS = "Iris OS/2.0 UPnP/1.0 Iris/2.0"


def ssdp(ip, server=IRIS, uuid=None):
    response = {"_ip": ip, "server": server, "st": "upnp:rootdevice"}
    if uuid:
        response["usn"] = f"uuid:{uuid}::upnp:rootdevice"
    return response


class FakeNetwork:
    """A fake LAN: an ARP table, SSDP responders, and hosts that answer SSH."""

    def __init__(self, monkeypatch, tmp_path):
        self.arp = []          # [(ip, mac)] -- empty models an unreadable table
        self.arp_after_discovery = None  # replaces arp once discovery has run
        self.responses = []    # SSDP responses
        self.hubs = {}         # ip -> eth0 MAC, for hosts that accept SSH
        self.refuse_ssh = set()
        self.discoveries = 0
        self.ssh_attempts = []

        monkeypatch.setattr(cli_mod, "_CACHE_PATH", tmp_path / "hosts.json")
        monkeypatch.setattr(cli_mod, "_read_arp", lambda: list(self.arp))
        monkeypatch.setattr(cli_mod, "_is_reachable", self._is_reachable)
        monkeypatch.setattr("arcushub.ssdp.discover", self._discover)
        # Patched at the paramiko seam, so the real _identify_hub runs.
        monkeypatch.setattr("arcushub.ssh.connect", self._connect)
        monkeypatch.setattr(cli_mod, "_run", lambda client, cmd, check=True: client.ifaces)

    def _is_reachable(self, ip, port=22, timeout=1.0):
        return ip in self.hubs and ip not in self.refuse_ssh

    def _discover(self, timeout=5.0):
        self.discoveries += 1
        if self.arp_after_discovery is not None:
            self.arp = self.arp_after_discovery
        return list(self.responses)

    def _connect(self, ip, **kwargs):
        self.ssh_attempts.append(ip)
        if ip not in self.hubs or ip in self.refuse_ssh:
            raise OSError(f"connection refused by {ip}")
        return _StubClient(
            f"/sys/class/net/lo/address 00:00:00:00:00:00\n"
            f"/sys/class/net/eth0/address {self.hubs[ip]}\n"
        )

    def cache(self, mapping):
        cli_mod._save_cache(mapping)

    def cached(self):
        return cli_mod._load_cache()


class _StubClient:
    def __init__(self, ifaces):
        self.ifaces = ifaces

    def close(self):
        pass


@pytest.fixture
def net(monkeypatch, tmp_path):
    return FakeNetwork(monkeypatch, tmp_path)


def test_non_hub_id_passes_through_untouched(net):
    assert cli_mod._resolve_host("172.16.1.42") == "172.16.1.42"
    assert cli_mod._resolve_host("hub.local") == "hub.local"
    assert net.discoveries == 0
    assert net.ssh_attempts == []


def test_readable_arp_resolves_without_discovery_or_ssh(net):
    net.arp = [(HUB_IP, HUB_MAC)]
    assert cli_mod._resolve_host(HUB_ID) == HUB_IP
    assert net.discoveries == 0
    assert net.ssh_attempts == []  # ARP is the fast path; don't SSH when it works


def test_matches_the_odd_mac_of_the_pair(net):
    # The hub ID encoding loses the low bit, so either MAC may be in the table
    net.arp = [(HUB_IP, "a0:19:b2:b0:23:09")]
    assert cli_mod._resolve_host(HUB_ID) == HUB_IP


def test_empty_arp_table_falls_back_to_ssh_identification(net):
    # The macOS case: the table is withheld, so no MAC ever matches
    net.arp = []
    net.responses = [ssdp(OTHER_IP), ssdp(HUB_IP)]
    net.hubs = {OTHER_IP: OTHER_MAC, HUB_IP: HUB_MAC}

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP
    assert net.discoveries == 1
    assert HUB_IP in net.ssh_attempts


def test_ssh_fallback_ignores_non_hub_responders(net):
    net.responses = [ssdp("172.16.1.60", "Linux/4.9.123 UPnP/1.0 GUPnP/0.20.13"), ssdp(HUB_IP)]
    net.hubs = {HUB_IP: HUB_MAC}

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP
    assert "172.16.1.60" not in net.ssh_attempts


def test_stale_cache_entry_resolves_to_the_current_ip(net):
    # The original failure: the hub moved under DHCP and the cache still had the old IP
    net.cache({HUB_ID: STALE_IP})
    net.responses = [ssdp(HUB_IP)]
    net.hubs = {HUB_IP: HUB_MAC}

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP
    assert net.cached()[HUB_ID] == HUB_IP


def test_cache_entry_pointing_at_another_hub_is_rejected(net):
    # STALE_IP answers SSH, but as a different hub
    net.cache({HUB_ID: STALE_IP})
    net.responses = [ssdp(HUB_IP)]
    net.hubs = {STALE_IP: OTHER_MAC, HUB_IP: HUB_MAC}

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP


def test_confirmed_cache_entry_skips_discovery(net):
    net.cache({HUB_ID: HUB_IP})
    net.hubs = {HUB_IP: HUB_MAC}

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP
    assert net.discoveries == 0


def test_cache_is_confirmed_by_arp_when_the_table_is_readable(net):
    net.cache({HUB_ID: HUB_IP})
    net.arp = [(HUB_IP, HUB_MAC)]
    net.hubs = {HUB_IP: HUB_MAC}

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP
    assert net.ssh_attempts == []
    assert net.discoveries == 0


def test_hubs_identified_along_the_way_are_cached(net):
    net.responses = [ssdp(OTHER_IP), ssdp(HUB_IP)]
    net.hubs = {OTHER_IP: OTHER_MAC, HUB_IP: HUB_MAC}

    cli_mod._resolve_host(HUB_ID)
    assert net.cached() == {OTHER_ID: OTHER_IP, HUB_ID: HUB_IP}


def test_hub_that_refuses_ssh_is_skipped_not_fatal(net):
    net.responses = [ssdp(OTHER_IP), ssdp(HUB_IP)]
    net.hubs = {OTHER_IP: OTHER_MAC, HUB_IP: HUB_MAC}
    net.refuse_ssh = {OTHER_IP}

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP


def test_not_found_names_the_hubs_that_answered(net):
    net.responses = [ssdp(OTHER_IP)]
    net.hubs = {OTHER_IP: OTHER_MAC}

    with pytest.raises(click.ClickException) as excinfo:
        cli_mod._resolve_host(HUB_ID)
    msg = excinfo.value.message
    assert HUB_ID in msg
    assert OTHER_IP in msg
    assert "ARP table came back empty" in msg


def test_not_found_omits_the_arp_hint_when_the_table_is_readable(net):
    net.arp = [(OTHER_IP, OTHER_MAC)]

    with pytest.raises(click.ClickException) as excinfo:
        cli_mod._resolve_host(HUB_ID)
    assert "ARP table came back empty" not in excinfo.value.message


def test_not_found_does_not_rule_out_hubs_it_could_not_identify(net):
    # A hub that refuses SSH may well be the one we want, so "none of them this
    # one" is only true of the responders we actually identified.
    net.responses = [ssdp(OTHER_IP), ssdp(HUB_IP)]
    net.hubs = {OTHER_IP: OTHER_MAC, HUB_IP: HUB_MAC}
    net.refuse_ssh = {HUB_IP}

    with pytest.raises(click.ClickException) as excinfo:
        cli_mod._resolve_host(HUB_ID)
    msg = excinfo.value.message
    assert f"1 hub(s) answered discovery ({OTHER_IP}), none of them this one." in msg
    assert f"could not be identified ({HUB_IP})" in msg


def test_not_found_with_every_hub_refusing_ssh_gives_the_way_out(net):
    net.responses = [ssdp(HUB_IP)]
    net.hubs = {HUB_IP: HUB_MAC}
    net.refuse_ssh = {HUB_IP}

    with pytest.raises(click.ClickException) as excinfo:
        cli_mod._resolve_host(HUB_ID)
    msg = excinfo.value.message
    assert "none of them this one" not in msg
    assert "Homebrew python" in msg
    assert "pass the hub's IP address" in msg


@pytest.mark.parametrize("suffix", ["::upnp:rootdevice", "", "::urn:schemas-upnp-org:device:Basic:1"])
def test_every_usn_form_a_hub_sends_gives_its_uuid(suffix):
    # The agent answers ssdp:all with these three forms, and any of them can be lost
    responses = [{"_ip": HUB_IP, "server": IRIS, "usn": f"uuid:{HUB_UUID}{suffix}"}]
    assert cli_mod._ssdp_hub_uuids(responses) == {HUB_IP: HUB_UUID}


def test_uuids_of_non_hub_responders_are_ignored():
    responses = [ssdp("172.16.1.60", "Linux/4.9.123 UPnP/1.0 GUPnP/0.20.13", uuid=OTHER_UUID)]
    assert cli_mod._ssdp_hub_uuids(responses) == {}


def test_moved_hub_is_recognised_by_uuid_with_arp_and_ssh_gone(net):
    # Identified over SSH once...
    net.responses = [ssdp(STALE_IP, uuid=HUB_UUID)]
    net.hubs = {STALE_IP: HUB_MAC}
    assert cli_mod._resolve_host(HUB_ID) == STALE_IP

    # ...then DHCP moves it and SSH closes
    net.ssh_attempts.clear()
    net.responses = [ssdp(HUB_IP, uuid=HUB_UUID)]
    net.hubs = {}

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP
    assert net.ssh_attempts == []
    assert net.cached()[HUB_ID] == HUB_IP


def test_hubs_visible_in_arp_after_discovery_are_remembered(net):
    # Learned while ARP works, for when it doesn't
    net.responses = [ssdp(HUB_IP, uuid=HUB_UUID), ssdp(OTHER_IP, uuid=OTHER_UUID)]
    net.arp_after_discovery = [(HUB_IP, HUB_MAC), (OTHER_IP, OTHER_MAC)]

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP
    assert cli_mod._known_hubs(net.responses) == {HUB_IP: HUB_MAC, OTHER_IP: OTHER_MAC}


def test_hub_known_to_be_another_one_is_not_logged_into(net):
    net.responses = [ssdp(OTHER_IP, uuid=OTHER_UUID)]
    net.hubs = {OTHER_IP: OTHER_MAC}
    with pytest.raises(click.ClickException):
        cli_mod._resolve_host(HUB_ID)  # identifies OTHER_IP over SSH and remembers it
    net.ssh_attempts.clear()

    with pytest.raises(click.ClickException) as excinfo:
        cli_mod._resolve_host(HUB_ID)
    assert net.ssh_attempts == []
    assert f"({OTHER_IP}), none of them this one." in excinfo.value.message


def test_remembering_a_hub_keeps_the_ones_already_known(net):
    net.responses = [ssdp(HUB_IP, uuid=HUB_UUID)]
    net.hubs = {HUB_IP: HUB_MAC}
    cli_mod._resolve_host(HUB_ID)

    net.responses = [ssdp(OTHER_IP, uuid=OTHER_UUID)]
    net.hubs = {OTHER_IP: OTHER_MAC}
    cli_mod._resolve_host(OTHER_ID)

    both = [ssdp(HUB_IP, uuid=HUB_UUID), ssdp(OTHER_IP, uuid=OTHER_UUID)]
    assert cli_mod._known_hubs(both) == {HUB_IP: HUB_MAC, OTHER_IP: OTHER_MAC}


def test_hub_announcing_an_unknown_uuid_is_still_asked_over_ssh(net):
    net.responses = [ssdp(HUB_IP, uuid=HUB_UUID)]
    net.hubs = {HUB_IP: HUB_MAC}

    assert cli_mod._resolve_host(HUB_ID) == HUB_IP
    assert net.ssh_attempts == [HUB_IP]


def test_connection_options_reach_the_identification_probe(net, monkeypatch):
    seen = {}

    def connect(ip, **kwargs):
        seen.update(kwargs)
        return net._connect(ip, **kwargs)

    monkeypatch.setattr("arcushub.ssh.connect", connect)
    net.responses = [ssdp(HUB_IP)]
    net.hubs = {HUB_IP: HUB_MAC}

    cli_mod._resolve_host(HUB_ID, port=2222, user="admin", password="hunter2")
    assert seen == {"port": 2222, "user": "admin", "password": "hunter2"}


def test_cache_survives_a_round_trip_through_resolution(net, tmp_path):
    net.responses = [ssdp(HUB_IP)]
    net.hubs = {HUB_IP: HUB_MAC}

    cli_mod._resolve_host(HUB_ID)
    assert json.loads((tmp_path / "hosts.json").read_text())[HUB_ID] == HUB_IP


def test_hubs_command_lists_hubs_when_arp_is_unreadable(net, monkeypatch):
    from click.testing import CliRunner

    net.responses = [ssdp(HUB_IP), ssdp(OTHER_IP)]
    net.hubs = {HUB_IP: HUB_MAC, OTHER_IP: OTHER_MAC}
    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **kw: _PingOK())

    result = CliRunner().invoke(cli_mod.cli, ["hubs"])
    assert result.exit_code == 0
    assert "No hubs found." not in result.output
    assert HUB_ID in result.output and HUB_IP in result.output
    assert OTHER_ID in result.output


def test_hubs_command_reports_responders_it_cannot_identify(net, monkeypatch):
    from click.testing import CliRunner

    net.responses = [ssdp(HUB_IP), ssdp(OTHER_IP)]
    net.hubs = {HUB_IP: HUB_MAC, OTHER_IP: OTHER_MAC}
    net.refuse_ssh = {OTHER_IP}
    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **kw: _PingOK())

    result = CliRunner().invoke(cli_mod.cli, ["hubs"])
    assert result.exit_code == 0
    assert HUB_ID in result.output
    assert f"could not be identified ({OTHER_IP})" in result.output
    assert "ARP table came back empty" in result.output


def test_hubs_command_with_unreadable_arp_and_ssh_closed_everywhere(net):
    # The 2026-10-30 failure: pipx on Homebrew python (no ARP table) and dropbear
    # down on every hub. Three hubs answered, and the output said "No hubs found."
    from click.testing import CliRunner

    ips = [HUB_IP, OTHER_IP, STALE_IP]
    net.responses = [ssdp(ip) for ip in ips]
    net.hubs = {HUB_IP: HUB_MAC, OTHER_IP: OTHER_MAC, STALE_IP: "00:16:a2:02:83:a4"}
    net.refuse_ssh = set(ips)

    result = CliRunner().invoke(cli_mod.cli, ["hubs"])
    assert result.exit_code == 0
    assert "No hubs found." not in result.output
    assert f"3 hub(s) answered discovery but could not be identified ({', '.join(ips)})" in result.output
    assert "ARP table came back empty" in result.output
    assert "Homebrew python" in result.output


def test_hubs_command_lists_hubs_it_saw_in_arp_once_arp_and_ssh_are_gone(net, monkeypatch):
    # The whole point of the UUID cache: the 2026-10-30 failure after one good run
    from click.testing import CliRunner

    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **kw: _PingOK())
    net.arp = [(STALE_IP, HUB_MAC)]
    net.responses = [ssdp(STALE_IP, uuid=HUB_UUID)]
    CliRunner().invoke(cli_mod.cli, ["hubs"])

    net.arp = []
    net.responses = [ssdp(HUB_IP, uuid=HUB_UUID)]
    result = CliRunner().invoke(cli_mod.cli, ["hubs"])
    assert result.exit_code == 0
    assert HUB_ID in result.output and HUB_IP in result.output and HUB_MAC in result.output
    assert "could not be identified" not in result.output
    assert net.ssh_attempts == []


def test_hubs_command_remembers_a_hub_it_identified_over_ssh(net, monkeypatch):
    from click.testing import CliRunner

    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **kw: _PingOK())
    net.responses = [ssdp(HUB_IP, uuid=HUB_UUID)]
    net.hubs = {HUB_IP: HUB_MAC}
    CliRunner().invoke(cli_mod.cli, ["hubs"])
    assert cli_mod._known_hubs(net.responses) == {HUB_IP: HUB_MAC}


def test_hubs_command_needs_no_ssh_when_the_arp_table_is_readable(net, monkeypatch):
    # These hosts do accept SSH, so that a stray attempt reaches connect and gets recorded.
    from click.testing import CliRunner

    net.arp = [(HUB_IP, HUB_MAC), (OTHER_IP, OTHER_MAC), ("172.16.1.1", "aa:bb:cc:dd:ee:ff")]
    net.responses = [ssdp(HUB_IP), ssdp(OTHER_IP)]
    net.hubs = {HUB_IP: HUB_MAC, OTHER_IP: OTHER_MAC}
    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **kw: _PingOK())

    result = CliRunner().invoke(cli_mod.cli, ["hubs"])
    assert result.exit_code == 0
    assert HUB_ID in result.output and OTHER_ID in result.output
    assert net.ssh_attempts == []
    assert "ARP table came back empty" not in result.output


def test_hubs_command_omits_the_arp_hint_when_the_table_is_readable(net):
    # Readable, but the responder isn't in it: reinstalling would change nothing
    from click.testing import CliRunner

    net.arp = [("172.16.1.1", "aa:bb:cc:dd:ee:ff")]
    net.responses = [ssdp(HUB_IP)]

    result = CliRunner().invoke(cli_mod.cli, ["hubs"])
    assert f"could not be identified ({HUB_IP})" in result.output
    assert "ARP table came back empty" not in result.output


def test_hubs_command_still_says_none_when_nothing_answered(net):
    from click.testing import CliRunner

    result = CliRunner().invoke(cli_mod.cli, ["hubs"])
    assert result.exit_code == 0
    assert "No hubs found." in result.output


class _PingOK:
    returncode = 0


def test_ssh_command_hands_its_connection_options_to_resolution(monkeypatch):
    # Resolution may need to SSH to identify a hub, so --port/--user/--password
    # have to reach it -- not just the final connection.
    from click.testing import CliRunner
    from conftest import FakeClient

    seen = {}

    def fake_resolve(host, **kwargs):
        seen["host"] = host
        seen.update(kwargs)
        return HUB_IP

    monkeypatch.setattr(cli_mod, "_resolve_host", fake_resolve)
    monkeypatch.setattr(cli_mod, "_connect", lambda *a, **kw: FakeClient())

    result = CliRunner().invoke(
        cli_mod.cli,
        ["ssh", "--port", "2222", "--user", "admin", "--password", "pw", HUB_ID, "echo", "hi"],
    )
    assert result.exit_code == 0
    assert seen == {"host": HUB_ID, "port": 2222, "user": "admin", "password": "pw"}

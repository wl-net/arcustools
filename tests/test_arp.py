from arcushub import cli as cli_mod
from arcushub.cli import (
    _is_hub_id,
    _parse_arp_a,
    _parse_iface_macs,
    _parse_proc_arp,
    _ssdp_hub_candidates,
)

PROC_ARP = """\
IP address       HW type     Flags       HW address            Mask     Device
172.16.1.57      0x1         0x2         00:16:a2:04:8b:64     *        enp5s0
172.16.1.19      0x1         0x0         00:16:a2:02:83:a4     *        enp5s0
172.16.1.20      0x1         0x2         0:16:a2:2:83:a4       *        enp5s0
172.16.1.99      0x1         0x0         00:00:00:00:00:00     *        enp5s0
"""


def test_proc_arp_skips_incomplete_entries():
    # .19 is a stale FAILED entry still holding the hub's old MAC; it must not match
    assert _parse_proc_arp(PROC_ARP) == [
        ("172.16.1.57", "00:16:a2:04:8b:64"),
        ("172.16.1.20", "00:16:a2:02:83:a4"),
    ]


def test_arp_a_parsing():
    text = (
        "? (172.16.1.20) at 0:16:a2:2:83:a4 on en0 ifscope [ethernet]\n"
        "? (172.16.1.21) at (incomplete) on en0 ifscope [ethernet]\n"
    )
    assert _parse_arp_a(text) == [("172.16.1.20", "00:16:a2:02:83:a4")]


def test_is_hub_id():
    assert _is_hub_id("LWH-7138")
    assert _is_hub_id("hfh-7156")
    assert not _is_hub_id("LW-7138")
    assert not _is_hub_id("172.16.1.20")
    assert not _is_hub_id("hub.local")


class _StubClient:
    """Stands in for an SSH client; the _run that would use it is patched out."""
    def close(self):
        pass


SSDP_RESPONSES = [
    {"_ip": "172.16.1.42", "server": "Iris OS/2.0 UPnP/1.0 Iris/2.0", "st": "upnp:rootdevice"},
    {"_ip": "172.16.1.42", "server": "Iris OS/2.0 UPnP/1.0 Iris/2.0", "st": "urn:schemas-upnp-org:device:Basic:1"},
    {"_ip": "172.16.1.60", "server": "Linux/4.9.123 UPnP/1.0 GUPnP/0.20.13"},
    {"_ip": "172.16.1.57", "server": "Iris OS/2.0 UPnP/1.0 Iris/2.0"},
    {"server": "Iris OS/2.0 UPnP/1.0 Iris/2.0"},  # no _ip
    {"_ip": "172.16.1.65"},  # no server header
]


def test_ssdp_hub_candidates_dedupes_and_filters():
    # Hubs only, each IP once, in the order they answered
    assert _ssdp_hub_candidates(SSDP_RESPONSES) == ["172.16.1.42", "172.16.1.57"]


def test_parse_iface_macs():
    text = (
        "/sys/class/net/eth0/address a0:19:b2:b0:23:08\n"
        "/sys/class/net/lo/address 00:00:00:00:00:00\n"
        "/sys/class/net/sit0/address 00:00:00:00\n"  # too short to be a MAC
        "/sys/class/net/wlan0/address d0:c5:d3:47:89:95\n"
        "cat: can't open '/sys/class/net/bogus/address': No such file\n"
    )
    assert _parse_iface_macs(text) == {
        "eth0": "a0:19:b2:b0:23:08",
        "lo": "00:00:00:00:00:00",
        "wlan0": "d0:c5:d3:47:89:95",
    }


def test_identify_hub_prefers_eth0_over_other_arcus_macs(monkeypatch):
    # br0 sorts ahead of eth0, but eth0 is the MAC the hub ID encodes
    text = (
        "/sys/class/net/br0/address 00:16:a2:04:8b:64\n"
        "/sys/class/net/eth0/address a0:19:b2:b0:23:08\n"
    )
    monkeypatch.setattr(cli_mod, "_is_reachable", lambda *a, **kw: True)
    monkeypatch.setattr(cli_mod, "_run", lambda *a, **kw: text)
    monkeypatch.setattr("arcushub.ssh.connect", lambda *a, **kw: _StubClient())
    assert cli_mod._identify_hub("172.16.1.42") == ("HFH-7156", "a0:19:b2:b0:23:08")


def test_identify_hub_ignores_non_hubs(monkeypatch):
    monkeypatch.setattr(cli_mod, "_is_reachable", lambda *a, **kw: True)
    monkeypatch.setattr(cli_mod, "_run", lambda *a, **kw: "/sys/class/net/eth0/address b8:27:eb:f2:a5:d1\n")
    monkeypatch.setattr("arcushub.ssh.connect", lambda *a, **kw: _StubClient())
    assert cli_mod._identify_hub("172.16.1.96") is None


def test_identify_hub_skips_hosts_that_refuse_ssh(monkeypatch):
    monkeypatch.setattr(cli_mod, "_is_reachable", lambda *a, **kw: False)
    assert cli_mod._identify_hub("172.16.1.41") is None

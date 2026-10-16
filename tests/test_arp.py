from arcushub.cli import _is_hub_id, _parse_arp_a, _parse_proc_arp

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

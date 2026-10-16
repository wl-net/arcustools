import random

import pytest

from arcushub.hubid import KNOWN_OUIS, hub_id_to_mac, mac_to_hub_id

# Real hubs: (hub ID, MAC)
KNOWN = [
    ("LWH-7138", "00:16:a2:02:83:a4"),  # v2
    ("LWR-3666", "00:16:a2:04:8b:64"),  # v2
    ("HFH-7156", "a0:19:b2:b0:23:08"),  # v3
]


@pytest.mark.parametrize("hub_id,mac", KNOWN)
def test_known_mac_to_hub_id(hub_id, mac):
    assert mac_to_hub_id(mac) == hub_id


@pytest.mark.parametrize("hub_id,mac", KNOWN)
def test_known_hub_id_to_mac(hub_id, mac):
    assert hub_id_to_mac(hub_id) == mac


def test_odd_mac_maps_to_same_hub_id():
    # The LSB is dropped by the encoding, so a hub's even and odd MACs share an ID
    assert mac_to_hub_id("00:16:a2:02:83:a5") == "LWH-7138"


def test_lowercase_hub_id_accepted():
    assert hub_id_to_mac("lwh-7138") == "00:16:a2:02:83:a4"


@pytest.mark.parametrize("oui", KNOWN_OUIS)
def test_round_trip(oui):
    rng = random.Random(oui)
    for _ in range(500):
        mac_long = (oui << 24) | rng.randrange(0, 1 << 24)
        mac = ":".join(f"{(mac_long >> s) & 0xFF:02x}" for s in range(40, -8, -8))
        even = ":".join(f"{(mac_long & ~1) >> s & 0xFF:02x}" for s in range(40, -8, -8))
        assert hub_id_to_mac(mac_to_hub_id(mac)) == even


@pytest.mark.parametrize("bad", ["LWI-1234", "LW-1234", "LWHH7138", "LWH-71"])
def test_invalid_hub_id(bad):
    with pytest.raises(ValueError):
        hub_id_to_mac(bad)

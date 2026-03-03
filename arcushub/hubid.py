"""Hub ID <-> MAC address conversion.

Hub IDs are encoded from the hub's MAC address using a base-23 scheme
over the alphabet ABCDEFGHJKLNPQRSTUVWXYZ (no I, M, O).

The encoding uses modulo 23 arithmetic, which is lossy — multiple MACs
map to the same hub ID. To reverse the mapping we need to know the
hub's OUI (first 3 bytes of the MAC).
"""

ALLOWED_CHARS = "ABCDEFGHJKLNPQRSTUVWXYZ"
ALLOWED_SIZE = len(ALLOWED_CHARS)
_CHAR_TO_INDEX = {c: i for i, c in enumerate(ALLOWED_CHARS)}
_CHAR_MOD = ALLOWED_SIZE ** 3  # 12167

# Known OUIs for Arcus hubs (most common first)
KNOWN_OUIS = [
    0x0016A2,  # v2 hubs
    0xA019B2,  # v3 hubs
]


def hub_id_to_mac(hub_id: str) -> str:
    """Convert a hub ID (e.g. LWR-2389) to a MAC address.

    Uses known OUIs to reconstruct the full MAC from the lossy hub ID encoding.
    The LSB is lost in the encoding, so this returns the even MAC.
    """
    hub_id = hub_id.upper()
    if len(hub_id) != 8 or hub_id[3] != "-":
        raise ValueError(f"Invalid hub ID format: {hub_id!r}")

    fst, snd, thd = hub_id[0], hub_id[1], hub_id[2]
    digits = int(hub_id[4:])

    for c in (fst, snd, thd):
        if c not in _CHAR_TO_INDEX:
            raise ValueError(f"Invalid character {c!r} in hub ID (allowed: {ALLOWED_CHARS})")

    char_value = (_CHAR_TO_INDEX[fst] * ALLOWED_SIZE * ALLOWED_SIZE
                  + _CHAR_TO_INDEX[snd] * ALLOWED_SIZE
                  + _CHAR_TO_INDEX[thd])

    for oui in KNOWN_OUIS:
        mac_min = oui << 24
        mac_max = mac_min | 0xFFFFFF
        macl_min = mac_min >> 1
        macl_max = mac_max >> 1

        # remainder = macl // 10000, and we need remainder % 12167 == char_value
        # So remainder = char_value + k * 12167 for some integer k
        rem_min = (macl_min - digits) // 10000
        rem_max = (macl_max - digits) // 10000

        k_min = -(-max(0, rem_min - char_value) // _CHAR_MOD)  # ceiling division
        k_max = (rem_max - char_value) // _CHAR_MOD

        for k in range(k_min, k_max + 1):
            remainder = char_value + k * _CHAR_MOD
            macl = remainder * 10000 + digits
            mac_long = macl << 1
            if mac_min <= mac_long <= mac_max:
                return _long_to_mac(mac_long)

    raise ValueError(f"Could not determine MAC for hub ID {hub_id} with known OUIs")


def mac_to_hub_id(mac: str) -> str:
    """Convert a MAC address to a hub ID."""
    mac_long = _mac_to_long(mac)
    macl = mac_long >> 1
    digits = (macl % 10000) & 0xFFFF
    remainder = macl // 10000

    thd = ALLOWED_CHARS[remainder % ALLOWED_SIZE]
    remainder //= ALLOWED_SIZE
    snd = ALLOWED_CHARS[remainder % ALLOWED_SIZE]
    remainder //= ALLOWED_SIZE
    fst = ALLOWED_CHARS[remainder % ALLOWED_SIZE]

    return f"{fst}{snd}{thd}-{digits:04d}"


def _mac_to_long(mac: str) -> int:
    """Parse a MAC address string to a 48-bit integer."""
    mac = mac.replace(":", "").replace("-", "").replace(".", "")
    if len(mac) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return int(mac, 16)


def _long_to_mac(val: int) -> str:
    """Format a 48-bit integer as a colon-separated MAC address."""
    hexstr = f"{val:012x}"
    return ":".join(hexstr[i:i+2] for i in range(0, 12, 2))

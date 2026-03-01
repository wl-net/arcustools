import re
import zipfile
from pathlib import Path

HUB_ID_RE = re.compile(r"^([A-Z]{2,3})-(\d{4})$")

VERSION_MAP = {
    "LW": "v2",
    "HF": "v3",
    "HG": "v3",
    "HH": "v3",
}


def parse_hub_id(hub_id: str) -> tuple[str, str]:
    """Parse a hub ID into (prefix, number). Raises ValueError if invalid."""
    m = HUB_ID_RE.match(hub_id.upper())
    if not m:
        raise ValueError(f"Invalid hub ID format: {hub_id!r} (expected e.g. LWC-8045)")
    return m.group(1), m.group(2)


def detect_version(prefix: str) -> str:
    """Detect firmware version from the hub prefix (first 2 chars)."""
    key = prefix[:2]
    version = VERSION_MAP.get(key)
    if not version:
        raise ValueError(
            f"Unknown hub prefix: {prefix!r} (expected LW* for v2, HF*/HG*/HH* for v3)"
        )
    return version


def find_zip(data_dir: Path, version: str, prefix: str) -> Path:
    """Locate the debug key ZIP for a given prefix."""
    zip_path = data_dir / version / "debug_keys" / f"{prefix}-xxxx.zip"
    if not zip_path.exists():
        raise FileNotFoundError(f"Debug key archive not found: {zip_path}")
    return zip_path


def extract_debug_key(hub_id: str, data_dir: Path, output_dir: Path) -> Path:
    """Extract the .dbg file for a hub ID and return the output path."""
    hub_id = hub_id.upper()
    prefix, _number = parse_hub_id(hub_id)
    version = detect_version(prefix)
    zip_path = find_zip(data_dir, version, prefix)

    member_name = f"{prefix}-xxxx/{hub_id}.dbg"
    with zipfile.ZipFile(zip_path) as zf:
        if member_name not in zf.namelist():
            raise KeyError(f"{hub_id}.dbg not found in {zip_path.name}")
        data = zf.read(member_name)

    output_path = output_dir / f"{hub_id}.dbg"
    output_path.write_bytes(data)
    return output_path

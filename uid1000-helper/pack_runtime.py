#!/usr/bin/env python3
"""Pack the Aloha watchdog library and DEX bootstrap into one staged blob."""

from __future__ import annotations

import pathlib
import struct
import sys


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: pack_runtime.py LIBRARY BOOTSTRAP OUTPUT")
    library = pathlib.Path(sys.argv[1]).read_bytes()
    bootstrap = pathlib.Path(sys.argv[2]).read_bytes()
    if not library.startswith(b"\x7fELF") or not bootstrap.startswith(b"PK\x03\x04"):
        raise SystemExit("unexpected Aloha runtime input format")
    header = struct.pack("<4sIII", b"PCR1", len(library), len(bootstrap), 0)
    pathlib.Path(sys.argv[3]).write_bytes(header + library + bootstrap)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

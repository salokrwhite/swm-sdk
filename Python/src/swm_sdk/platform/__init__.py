from __future__ import annotations

import platform as host_platform
import struct
import sys

if (
    sys.platform == "win32"
    and host_platform.machine().lower() in {"amd64", "x86_64", "x86", "i386"}
    and struct.calcsize("P") in {4, 8}
):
    from .windows import (
        IdentityKey,
        collect_hardware_evidence,
        protect,
        supported,
        unprotect,
    )
else:
    from .unsupported import (  # type: ignore[assignment]
        IdentityKey,
        collect_hardware_evidence,
        protect,
        supported,
        unprotect,
    )

__all__ = [
    "IdentityKey",
    "collect_hardware_evidence",
    "protect",
    "supported",
    "unprotect",
]

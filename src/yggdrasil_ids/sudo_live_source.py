"""Coordinate private snapshot readers with the existing sudo poll writer."""

from __future__ import annotations

import fcntl
import os
import stat
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def source_snapshot_guard(database: Path):
    """Fail promptly when the journal poll is still writing its staged batch.

    Use the same lock inode as sprint5_sudo_shadow_poll, never create or replace
    it here. A crashed poll can leave validated partial rows, so snapshots are
    still provisional and cannot establish complete journal coverage.
    """
    fd = os.open(database.parent / "shadow-poll.lock", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise PermissionError("Private sudo poll lock ownership is required")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)

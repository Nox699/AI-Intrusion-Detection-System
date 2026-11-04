"""Private, deterministic sudo journal fixtures; never installed with the package."""

NOW = 1_800_000_000.0
BOOT = "a" * 32


def row(index, stamp, kind="failure"):
    messages = {
        "failure": "pam_unix(sudo:auth): authentication failure; logname=private-user",
        "summary": "private-user : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/private",
        "success": "pam_unix(sudo:session): session opened for user root(uid=0) by private-user",
        "denied": "private-user is not in the sudoers file.",
    }
    return {
        "_EXE": "/usr/bin/sudo",
        "_UID": "1000",
        "_PID": str(4000 + index),
        "_BOOT_ID": BOOT,
        "__CURSOR": f"private-cursor-{index}-{kind}",
        "__REALTIME_TIMESTAMP": str(round(stamp * 1_000_000)),
        "MESSAGE": messages[kind],
    }

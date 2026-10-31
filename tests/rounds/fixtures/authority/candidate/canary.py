"""Invented canaries only; never real credentials or Actions command files."""

import errno
import json
import os
from pathlib import Path


def probe(phase):
    result = {"phase": phase, "uid": os.getuid(), "gid": os.getgid(), "attempts": []}
    for operation, name in [
        ("read", "/inputs/source/credential"),
        ("write", "/inputs/context.json"),
        ("write", "/inputs/source/actions/GITHUB_OUTPUT"),
        ("write", "/proc/1/root/inputs/context.json"),
    ]:
        try:
            if operation == "read":
                Path(name).read_bytes()
            else:
                Path(name).write_text("forged")
        except OSError as error:
            result["attempts"].append(
                {
                    "op": operation,
                    "path": name,
                    "errno": error.errno,
                    "denied": error.errno in (errno.EACCES, errno.EROFS, errno.EPERM),
                }
            )
        else:
            result["attempts"].append({"op": operation, "path": name, "denied": False})
    result["forbidden_env_present"] = sorted(
        key
        for key in (
            "GITHUB_TOKEN",
            "ACTIONS_RUNTIME_TOKEN",
            "GITHUB_ENV",
            "GITHUB_OUTPUT",
            "SSH_AUTH_SOCK",
            "DOCKER_HOST",
        )
        if key in os.environ
    )
    result["docker_socket_present"] = Path("/var/run/docker.sock").exists()
    result["proc_status"] = {
        line.split(":")[0]: line.split(":", 1)[1].strip()
        for line in Path("/proc/self/status").read_text().splitlines()
        if line.startswith(("CapEff:", "NoNewPrivs:"))
    }
    Path("/out/" + phase + ".json").write_text(json.dumps(result))

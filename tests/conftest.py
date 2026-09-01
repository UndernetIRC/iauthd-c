"""pytest fixtures: drive undernet-development-env and test against it."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest
import pytest_asyncio

from irc_client import IRCClient

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = Path(__file__).resolve().parent

UNDERNET_ENV = Path(
    os.environ.get(
        "UNDERNET_ENV",
        str(Path.home() / "undernet-development-env"),
    )
).expanduser().resolve()

# Client on leaf; VERIFY fake peer links to the hub's published S2S port.
LEAF = {
    "host": "127.0.0.1",
    "port": 6667,
    "server_port": 4400,
    "name": "leaf.undernet.org",
    "hub_name": "hub.undernet.org",
}

# Marker block injected into undernet etc/hub.conf for the host-side VERIFY peer.
_HUB_MARKER_BEGIN = "# BEGIN iauthd-c-integration"
_HUB_MARKER_END = "# END iauthd-c-integration"
_HUB_INJECT = f"""{_HUB_MARKER_BEGIN}
# Host-side VERIFY peer (pytest). Connections via published :4400 appear as the bridge gateway.
Connect {{
        name = "verify.test.net";
        host = "10.5.0.1";
        password = "testpass";
        class = "Server";
}};
{_HUB_MARKER_END}
"""

_stack_started = False
_cfg_backups: dict[Path, str | None] = {}


def wait_for_port(host: str, port: int, timeout: float = 60.0):
    """Block until a TCP port is accepting connections."""
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    raise TimeoutError(f"Port {host}:{port} not ready after {timeout}s")


def undernet_compose(*args, check=True, env: dict | None = None):
    """Run ``docker compose`` inside undernet-development-env (core stack)."""
    if not (UNDERNET_ENV / "docker-compose.yml").is_file():
        raise RuntimeError(
            f"undernet-development-env not found at {UNDERNET_ENV}.\n"
            "Clone/set UNDERNET_ENV to your undernet-development-env checkout."
        )
    run_env = os.environ.copy()
    # Rebuild hub/leaf with *this* iauthd-c tree.
    run_env["IAUTHD_SRC"] = str(REPO_ROOT)
    # Do not auto-enable the optional cservice profile.
    run_env["COMPOSE_PROFILES"] = ""
    if env:
        run_env.update(env)
    result = subprocess.run(
        ["docker", "compose", *args],
        capture_output=True,
        text=True,
        timeout=1200,
        cwd=UNDERNET_ENV,
        env=run_env,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"undernet compose {' '.join(args)} failed:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _backup_and_write(path: Path, content: str):
    if path not in _cfg_backups:
        _cfg_backups[path] = path.read_text() if path.is_file() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _inject_hub_connects(hub_conf: Path):
    text = hub_conf.read_text() if hub_conf.is_file() else ""
    if hub_conf not in _cfg_backups:
        _cfg_backups[hub_conf] = text if hub_conf.is_file() else None
    if _HUB_MARKER_BEGIN in text:
        pre, rest = text.split(_HUB_MARKER_BEGIN, 1)
        if _HUB_MARKER_END in rest:
            _, post = rest.split(_HUB_MARKER_END, 1)
            text = pre.rstrip() + "\n\n" + _HUB_INJECT + post.lstrip("\n")
        else:
            text = pre.rstrip() + "\n\n" + _HUB_INJECT + "\n"
    else:
        text = text.rstrip() + "\n\n" + _HUB_INJECT + "\n"
    hub_conf.write_text(text)


def _install_test_configs():
    iauthd_src = TESTS_DIR / "undernet" / "iauthd-c.conf"
    _backup_and_write(
        UNDERNET_ENV / "etc" / "iauthd-c.conf",
        iauthd_src.read_text(),
    )
    _inject_hub_connects(UNDERNET_ENV / "etc" / "hub.conf")


def _restore_test_configs():
    for path, original in list(_cfg_backups.items()):
        if original is None:
            if path.is_file():
                path.unlink()
        else:
            path.write_text(original)
    _cfg_backups.clear()


def _wait_gnuworld_linked(timeout: float = 120.0):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        result = undernet_compose(
            "logs", "--no-color", "--tail", "80", "gnuworld", check=False
        )
        text = (result.stdout or "") + (result.stderr or "")
        last = text[-800:]
        if any(
            n in text
            for n in (
                "Connected to",
                "Connection established",
                "Burst completed",
                "Completed burst",
                "NetBurst",
            )
        ):
            time.sleep(2)
            return
        status = undernet_compose("ps", "gnuworld", check=False)
        out = status.stdout or ""
        if "Exit" in out or "exited" in out.lower():
            raise RuntimeError(f"gnuworld exited before linking:\n{text}")
        time.sleep(1)
    raise TimeoutError(f"gnuworld did not uplink within {timeout}s:\n{last}")


def _start_stack():
    global _stack_started
    _install_test_configs()
    # Force recreate so bind-mounted hub.conf / iauthd-c.conf are loaded.
    undernet_compose(
        "up",
        "--build",
        "--force-recreate",
        "-d",
        "hub",
        "leaf",
        "db",
        "gnuworld",
    )
    wait_for_port(LEAF["host"], LEAF["port"], timeout=120.0)
    wait_for_port(LEAF["host"], LEAF["server_port"], timeout=60.0)
    _wait_gnuworld_linked()
    _stack_started = True


def pytest_sessionfinish(session, exitstatus):
    _restore_test_configs()
    if os.environ.get("UNDERNET_TEARDOWN", "").lower() in ("1", "true", "yes"):
        undernet_compose("down", "--remove-orphans", check=False)
    elif _stack_started:
        # Reload restored configs into the still-running stack.
        undernet_compose("restart", "hub", "leaf", check=False)


def iauthd_log(service: str = "leaf") -> str:
    """Return /tmp/iauthd-c.log from a hub/leaf container."""
    result = undernet_compose("exec", "-T", service, "cat", "/tmp/iauthd-c.log")
    return result.stdout


@pytest.fixture(scope="session")
def ircd_hub():
    """Ensure undernet-development-env is up (hub/leaf/db/gnuworld)."""
    if not _stack_started:
        _start_stack()
    yield LEAF


@pytest_asyncio.fixture
async def make_client(ircd_hub):
    """Factory for clients on the undernet leaf."""
    clients: list[IRCClient] = []

    async def _make(
        nick: str,
        user: str = "testuser",
        realname: str = "Test User",
        password: str | None = None,
        host: str | None = None,
        port: int | None = None,
        register_timeout: float = 20.0,
    ) -> IRCClient:
        client = IRCClient()
        await client.connect(host or ircd_hub["host"], port or ircd_hub["port"])
        if password is not None:
            await client.send(f"PASS :{password}")
        await client.register(nick, user, realname, timeout=register_timeout)
        clients.append(client)
        return client

    yield _make

    for client in clients:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        try:
            await client.disconnect()
        except Exception:
            pass

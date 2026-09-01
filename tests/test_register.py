"""Registration against undernet-development-env (real GNUWorld CHECK)."""

from __future__ import annotations

import asyncio

import pytest

from conftest import iauthd_log
from irc_client import IRCClient

pytestmark = pytest.mark.integration


@pytest.fixture
async def verify_ok_peer(ircd_hub):
    """Auto-OK VERIFY so registration tests are not blocked on the verify peer."""
    from xquery_service import XQueryService

    svc = XQueryService(
        name="verify.test.net",
        numeric=5,
        password="testpass",
    )
    await svc.connect(ircd_hub["host"], ircd_hub["server_port"])
    await svc.handshake()
    await svc.start_auto_ok(lambda *_: "OK")
    await asyncio.sleep(0.3)
    yield svc
    await svc.disconnect()


async def test_register_with_gnuworld_ok(make_client, verify_ok_peer):
    """Client registers when GNUWorld answers CHECK and VERIFY is auto-OK'd."""
    client = await make_client("oknick")
    assert client.nick == "oknick"

    log = iauthd_log("leaf")
    assert "CHECK " in log and " * :" in log, (
        f"expected CHECK with '*' in iauthd log, got tail:\n{log[-1500:]}"
    )


async def test_register_rejected_by_verify(ircd_hub, verify_ok_peer):
    """A NO reply from the VERIFY peer kills the connecting client."""
    await verify_ok_peer.stop_auto()

    async def deny(_hub, _routing, query: str):
        if query.startswith("VERIFY "):
            return "NO not welcome"
        return "OK"

    await verify_ok_peer.start_auto_ok(deny)

    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("NICK badbot")
        await client.send("USER testuser 0 * :Evil Bot")
        saw_kill = False
        deadline = asyncio.get_event_loop().time() + 20.0
        while asyncio.get_event_loop().time() < deadline:
            try:
                msg = await client.recv(timeout=2.0)
            except (TimeoutError, ConnectionError, OSError):
                saw_kill = True
                break
            if msg.command in ("ERROR", "465", "464"):
                saw_kill = True
                break
            if msg.command == "001":
                pytest.fail("client was accepted despite VERIFY NO")
        assert saw_kill, "expected kill/disconnect after VERIFY NO"
    finally:
        await client.disconnect()

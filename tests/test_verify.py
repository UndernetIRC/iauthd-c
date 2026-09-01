"""VERIFY service tests: account gating, MORE/AGAIN holds, edge cases.

Happy path:
  CAP + NICK/USER → SASL via gnuworld/cservice stamps account → VERIFY <account> →
  MORE / AGAIN (client notices with opaque text) → service OK → CAP END → 001.

Approval is out-of-band via the verify peer (not via client PASS).
MORE places a hard hold; soft timeout alone must not accept the client.

Edge cases cover no SASL (account ``*``), no CAP negotiation, CAP wait
until END without an account, and VERIFY NO.
"""

from __future__ import annotations

import asyncio
import base64

import pytest

from irc_client import IRCClient
from xquery_service import XQueryService

pytestmark = pytest.mark.integration

# Opaque MORE/AGAIN text relayed to the client as NOTICE AUTH.
VERIFY_MORE = "MORE Lorem ipsum dolor sit amet, consectetur adipiscing elit."
VERIFY_AGAIN = (
    "AGAIN Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
)

# Default cservice admin from undernet-development-env (cservice.addme / web README).
CSERVICE_USER = "Admin"
CSERVICE_PASS = "temPass2020@"


@pytest.fixture
async def verify_service(ircd_hub):
    """Host P10 peer for VERIFY (MORE/AGAIN/OK driven by the test)."""
    svc = XQueryService(
        name="verify.test.net",
        numeric=5,
        password="testpass",
    )
    await svc.connect(ircd_hub["host"], ircd_hub["server_port"])
    await svc.handshake()
    # Keep the link alive (PINGs) and buffer XQUERY for wait_for_iauth_query.
    await svc.start_auto_ok(lambda *_: None)
    await asyncio.sleep(0.3)
    yield svc
    await svc.disconnect()


async def _sasl_plain(client: IRCClient, username: str, password: str) -> None:
    """Complete SASL PLAIN against gnuworld/cservice; expect 903.

    GNUWorld requires a non-empty authzid (rejects the usual ``\\0user\\0pass``
    form), so we send ``user\\0user\\0pass``.
    """
    await client.send("AUTHENTICATE PLAIN")
    for _ in range(8):
        msg = await client.recv(timeout=5.0)
        if msg.command == "AUTHENTICATE" and msg.params and msg.params[0] == "+":
            payload = base64.b64encode(
                f"{username}\0{username}\0{password}".encode()
            ).decode()
            await client.send(f"AUTHENTICATE {payload}")
        if msg.command == "903":
            return
        if msg.command == "904":
            pytest.fail(f"SASL failed: {msg}")
    await client.wait_for("903", timeout=10.0)


async def _cap_nick_user_sasl(client: IRCClient, nick: str) -> None:
    """CAP + NICK/USER + SASL PLAIN so iauth receives ``A Admin`` from cservice."""
    await client.send("CAP LS 302")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert "sasl" in msg.params[-1], f"no sasl in CAP LS: {msg.params}"

    await client.send("CAP REQ :sasl")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert msg.params[1] == "ACK", msg.params

    await client.send(f"NICK {nick}")
    await client.send("USER testuser 0 * :Verify User")
    await asyncio.sleep(0.3)

    await _sasl_plain(client, CSERVICE_USER, CSERVICE_PASS)


async def _wait_notice_auth(client: IRCClient, needle: str, timeout: float = 10.0) -> str:
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            raise TimeoutError(f"no NOTICE AUTH containing {needle!r}")
        msg = await client.recv(timeout=remaining)
        if msg.command == "NOTICE" and msg.params and needle in msg.params[-1]:
            return msg.params[-1]


async def _expect_no_verify(verify_service: XQueryService, seconds: float = 2.0) -> None:
    """Assert VERIFY does not fire within ``seconds``."""
    try:
        await verify_service.wait_for_iauth_query(substring="VERIFY ", timeout=seconds)
    except TimeoutError:
        return
    pytest.fail(
        f"VERIFY fired unexpectedly: {[q for _, _, q in verify_service.queries]}"
    )


async def _verify_ok_and_welcome(
    client: IRCClient,
    verify_service: XQueryService,
    *,
    account: str,
    timeout: float = 15.0,
    cap_end: bool = False,
) -> str:
    """Wait for VERIFY with ``account``, reply OK, optionally CAP END, expect 001."""
    hub_num, routing, query = await verify_service.wait_for_iauth_query(
        substring="VERIFY ", timeout=timeout
    )
    assert query.startswith("VERIFY "), query
    needle = f" {account} :"
    assert needle in query, f"expected account {account!r} in VERIFY, got: {query!r}"
    await verify_service.reply(hub_num, routing, "OK")
    if cap_end:
        await client.send("CAP END")
    await client.wait_for("001", timeout=20.0)
    return query


async def test_verify_more_again_ok_with_account(ircd_hub, verify_service):
    """VERIFY includes cservice SASL account; MORE/AGAIN then OK → 001."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert "sasl" in msg.params[-1], msg.params

        await client.send("CAP REQ :sasl")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "ACK", msg.params

        await client.send("NICK verok1")
        await client.send("USER testuser 0 * :Verify User")
        await asyncio.sleep(0.5)

        await _expect_no_verify(verify_service, seconds=2.0)

        await _sasl_plain(client, CSERVICE_USER, CSERVICE_PASS)

        hub_num, routing, query = await verify_service.wait_for_iauth_query(
            substring="VERIFY ", timeout=15.0
        )
        assert f" {CSERVICE_USER} :" in query, (
            f"expected account in VERIFY, got: {query!r}"
        )

        await verify_service.reply(hub_num, routing, VERIFY_MORE)
        await _wait_notice_auth(client, "Lorem ipsum")

        await verify_service.reply(hub_num, routing, VERIFY_AGAIN)
        await _wait_notice_auth(client, "Sed do eiusmod")

        await verify_service.reply(hub_num, routing, "OK")
        await client.send("CAP END")
        await client.wait_for("001", timeout=20.0)
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_verify_timeout_after_more_not_accepted(ircd_hub, verify_service):
    """After VERIFY MORE (hard hold), soft timeout must not accept the client."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await _cap_nick_user_sasl(client, "verto1")

        hub_num, routing, query = await verify_service.wait_for_iauth_query(
            substring="VERIFY ", timeout=15.0
        )
        assert f" {CSERVICE_USER} :" in query, query
        await verify_service.reply(hub_num, routing, VERIFY_MORE)
        await _wait_notice_auth(client, "Lorem ipsum")

        await client.send("CAP END")

        saw_001 = False
        deadline = asyncio.get_event_loop().time() + 20.0
        while asyncio.get_event_loop().time() < deadline:
            try:
                msg = await client.recv(timeout=2.0)
            except (TimeoutError, ConnectionError, OSError):
                continue
            if msg.command == "001":
                saw_001 = True
                break
        assert not saw_001, (
            "client must not be accepted while VERIFY MORE hard-hold is active"
        )
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_verify_star_account_on_cap_end_without_sasl(ircd_hub, verify_service):
    """CAP without SASL: VERIFY waits until CAP END, then uses account ``*``."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("CAP REQ :sasl")
        await client.wait_for("CAP", timeout=5.0)

        await client.send("NICK vernosasl")
        await client.send("USER testuser 0 * :No SASL User")
        await asyncio.sleep(0.5)

        await _expect_no_verify(verify_service, seconds=2.0)

        await client.send("CAP END")
        await _verify_ok_and_welcome(
            client, verify_service, account="*", cap_end=False
        )
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_verify_no_cap_uses_star_account(ircd_hub, verify_service):
    """No CAP at all: VERIFY fires as soon as nick/user are ready, with ``*``."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("NICK vernocap")
        await client.send("USER testuser 0 * :No CAP User")
        await _verify_ok_and_welcome(client, verify_service, account="*")
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_verify_cap_ls_only_waits_until_end(ircd_hub, verify_service):
    """CAP LS without REQ/SASL still gates VERIFY until CAP END (account ``*``)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)

        await client.send("NICK vercapls")
        await client.send("USER testuser 0 * :CAP LS Only")
        await asyncio.sleep(0.5)

        await _expect_no_verify(verify_service, seconds=2.0)

        await client.send("CAP END")
        await _verify_ok_and_welcome(
            client, verify_service, account="*", cap_end=False
        )
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_verify_no_rejects_client(ircd_hub, verify_service):
    """VERIFY NO kills the client instead of welcoming them."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("NICK verno")
        await client.send("USER testuser 0 * :Denied")

        hub_num, routing, query = await verify_service.wait_for_iauth_query(
            substring="VERIFY ", timeout=15.0
        )
        assert " * :" in query, query
        await verify_service.reply(hub_num, routing, "NO verification failed")

        saw_kill = False
        deadline = asyncio.get_event_loop().time() + 15.0
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

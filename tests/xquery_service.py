"""Helpers for answering iauthd-c XQUERY traffic from a fake P10 service."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from p10_server import P10Server

logger = logging.getLogger("xquery_service")

ReplyHandler = Callable[[str, str, str], Awaitable[str | None] | str | None]


def parse_xquery(line: str) -> tuple[str, str, str]:
    """Parse a P10 XQ line into (hub_numeric, routing, query_text).

    Wire format: ``<hubnum> XQ <targetnum> <routing> :<query>``
    IAuth-originated queries use an ``iauth:`` routing prefix.
    """
    # Split trailing once so query text may contain spaces / colons.
    if " :" in line:
        head, query = line.split(" :", 1)
    else:
        parts = line.split(" ", 4)
        if len(parts) < 5:
            raise ValueError(f"malformed XQ line: {line!r}")
        return parts[0], parts[3], parts[4]

    parts = head.split()
    if len(parts) < 4:
        raise ValueError(f"malformed XQ line: {line!r}")
    return parts[0], parts[3], query


class XQueryService(P10Server):
    """P10 services peer with optional auto-replies to iauth XQUERY.

    A background reader always runs after ``start_auto_ok`` (even when the
    handler returns ``None``) so PINGs are answered and XQUERY lines are
    buffered for ``wait_for_iauth_query``.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._auto_task: asyncio.Task | None = None
        self._handler: ReplyHandler | None = None
        self.queries: list[tuple[str, str, str]] = []
        self._queries_consumed = 0
        self._query_event = asyncio.Event()

    async def start_auto_ok(self, handler: ReplyHandler | None = None):
        """Background-read XQ lines; reply when ``handler`` returns a string.

        ``handler(hub_num, routing, query)`` may return:
          - a reply string (sent as XR)
          - ``None`` to leave answering to the test (``wait_for_iauth_query``)
        """
        self._handler = handler if handler is not None else (lambda *_: "OK")
        if self._auto_task is not None:
            return
        self._auto_task = asyncio.create_task(self._auto_loop())

    async def stop_auto(self):
        if self._auto_task is not None:
            self._auto_task.cancel()
            try:
                await self._auto_task
            except asyncio.CancelledError:
                pass
            self._auto_task = None

    async def wait_for_iauth_query(
        self, substring: str | None = None, timeout: float = 10.0
    ) -> tuple[str, str, str]:
        """Wait for an iauth-originated XQUERY; return hub, routing, query."""
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            while self._queries_consumed < len(self.queries):
                hub_num, routing, query = self.queries[self._queries_consumed]
                self._queries_consumed += 1
                if not routing.startswith("iauth:"):
                    continue
                if substring is not None and substring not in query:
                    continue
                return hub_num, routing, query

            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for iauth XQUERY"
                    + (f" containing {substring!r}" if substring else "")
                )
            self._query_event.clear()
            try:
                await asyncio.wait_for(self._query_event.wait(), timeout=remaining)
            except TimeoutError:
                continue

    async def reply(self, hub_num: str, routing: str, reply: str):
        """Send an XREPLY for a previously received query."""
        await self.send_xreply(hub_num, routing, reply)

    async def _auto_loop(self):
        try:
            while self.connected:
                try:
                    line = await self.wait_for_token("XQ", timeout=1.0)
                except TimeoutError:
                    continue
                try:
                    hub_num, routing, query = parse_xquery(line)
                except ValueError:
                    logger.warning("skipping unparseable XQ: %s", line)
                    continue
                # iauthd CHECK/VERIFY/LOGIN use iauth:; SASL uses sasl:<cookie>.
                if not (
                    routing.startswith("iauth:") or routing.startswith("sasl:")
                ):
                    continue
                self.queries.append((hub_num, routing, query))
                self._query_event.set()
                handler = self._handler
                if handler is None:
                    continue
                result = handler(hub_num, routing, query)
                if asyncio.iscoroutine(result):
                    result = await result
                if result is not None:
                    await self.reply(hub_num, routing, result)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("auto XQUERY loop crashed")

    async def disconnect(self):
        await self.stop_auto()
        await super().disconnect()

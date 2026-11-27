"""One ``tools/call`` in flight at a time on a backend whose tools change state.

Some servers keep state the whole process shares and change it with awaits in
between: server-memory loads its graph, changes it and saves it, so two calls in
flight both start from the old graph and the last save wins (20 parallel writes
kept 1 entity). Serializing the calls keeps every write, and costs only the
queue wait. A browser server needs the same, because each call acts on the
"current" tab, which another caller's call could move.

The gate is on when ANY tool lacks ``readOnlyHint: true``
(:func:`needs_serialization`): positive evidence only, never a server name.
Kiro Crew's own servers read the caller block and are never gated.

The gate never awaits on the stub's read path: :meth:`CallGate.submit` queues
and returns, so a stub's own ``notifications/cancelled`` still gets through.
Every cancel path (the chat's own cancel, a Stop, a disconnect) goes through
:meth:`CallGate.cancel`: a call not yet written never reaches the server; one
already written keeps the slot until its reply, or :data:`CANCEL_GRACE_SECS`
after its cancel, since a server answers nothing to a call it cancelled.
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger("kiro_crew.mcp_gateway.backend")

#: How long a cancelled in-flight call keeps the slot before the next call runs.
CANCEL_GRACE_SECS = 5.0

#: Sends one queued frame; returns False when it sent nothing (the call was
#: cancelled first, or answered by the gateway), which frees the slot.
Writer = Callable[[str, dict[str, Any]], Awaitable[bool]]

DROPPED = "dropped"
UNSENT = "unsent"
SENT = "sent"
NOT_GATED = "not_gated"


def needs_serialization(tools: Any) -> bool:
    """True when some listed tool does not declare ``readOnlyHint: true``."""
    if not isinstance(tools, list) or not tools:
        return False
    for tool in tools:
        ann = tool.get("annotations") if isinstance(tool, dict) else None
        if not (isinstance(ann, dict) and ann.get("readOnlyHint") is True):
            return True
    return False


class CallGate:
    """FIFO of forwarded ``tools/call`` frames; one is written at a time.

    *write* sends one frame upstream under its forward id; it runs after any
    per-call preparation the frame was queued with, and before the slot can be
    released by that frame's reply.
    """

    def __init__(self, write: Writer) -> None:
        self._write = write
        self._queue: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        self._current: Optional[str] = None
        # Whether the frame of the call in flight has been written, and whether
        # it was cancelled before it was.
        self._sent = False
        self._unwanted = False
        self._task: Optional["asyncio.Task[None]"] = None
        self._grace: Optional[asyncio.TimerHandle] = None

    @property
    def in_flight(self) -> Optional[str]:
        return self._current

    def queued(self) -> list[str]:
        return list(self._queue)

    def submit(self, fid: str, frame: dict[str, Any]) -> None:
        """Queue *frame* under *fid*; it is written when the slot is free."""
        self._queue[fid] = frame
        self._pump()

    def release(self, fid: str) -> None:
        """The call *fid* ended (a reply, or none can arrive): free its slot."""
        if self._queue.pop(fid, None) is not None:
            return
        if fid == self._current:
            self._current = None
            if self._grace is not None:
                self._grace.cancel()
                self._grace = None
            self._pump()

    def rekey(self, old: str, new: str) -> None:
        """The call in flight as *old* was re-sent as *new* (a rehandshake retry)."""
        if self._current == old:
            self._current = new

    def cancel(self, fid: str) -> str:
        """*fid* was cancelled (by its chat, a Stop, or a disconnect). Returns what that means.

        ``DROPPED``: it was queued and is forgotten; ``UNSENT``: it holds the slot
        but its frame is not out yet, so the writer sends nothing and frees the
        slot; for both the server never sees the call, so no upstream cancel is
        owed. ``SENT``: it is running, so the upstream cancel goes out and the
        slot frees on its reply or :data:`CANCEL_GRACE_SECS` later.
        ``NOT_GATED``: the gate never held it.
        """
        if self._queue.pop(fid, None) is not None:
            return DROPPED
        if fid != self._current:
            return NOT_GATED
        if not self._sent:
            self._unwanted = True
            return UNSENT
        if self._grace is None:
            loop = asyncio.get_running_loop()
            self._grace = loop.call_later(CANCEL_GRACE_SECS, self.release, fid)
        return SENT

    def mark_sending(self, fid: str) -> None:
        """*fid*'s frame goes out now: a cancel from here on is ``SENT``."""
        if fid == self._current:
            self._sent = True

    def wanted(self, fid: str) -> bool:
        """Whether *fid* holds the slot and was not cancelled: the writer's last check."""
        return fid == self._current and not self._unwanted

    def fail_all(self) -> None:
        """The backend is gone: forget every queued call and the one in flight."""
        self._queue.clear()
        self._current = None
        if self._grace is not None:
            self._grace.cancel()
            self._grace = None

    def _pump(self) -> None:
        if self._current is not None or not self._queue:
            return
        fid, frame = self._queue.popitem(last=False)
        self._current = fid
        self._sent = False
        self._unwanted = False
        self._task = asyncio.get_running_loop().create_task(self._send(fid, frame))

    async def _send(self, fid: str, frame: dict[str, Any]) -> None:
        try:
            sent = await self._write(fid, frame)
        except Exception:
            # The write failed (a closed pipe): the backend-gone path settles
            # every pending call; this one gets no reply, so free the slot.
            logger.debug("call gate: write of %s failed", fid, exc_info=True)
            sent = False
        if not sent:
            self.release(fid)
        elif self._current == fid:
            self._sent = True

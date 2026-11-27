"""Per-caller adjustments of a shared ``Backend``: folders and roots.

:func:`scope_forward` is the ONE place a stub's request is adjusted for the
caller that sent it, after the gateway has named that caller and before the
frame is written to the backend. A later per-caller rule (call serialization, a
per-caller browser tab) belongs here, not at a second site.

What it does today (:mod:`kiro_crew.mcp_gateway.folder_scope`):

* a ``tools/call`` to a third-party server gets its relative folder arguments
  made absolute against the caller's folder, and a missing required one filled;
* a server's ``roots/list`` is answered by the gateway with every attached
  caller's folder (:func:`serve_roots`), and ``notifications/roots/list_changed``
  is sent when that set changes (:func:`note_caller`, :func:`forget_stub`), so
  the backend is not recycled and the server is not kept one copy per chat.

Kiro Crew's own servers (``supports_caller_identity``) are never adjusted: they
read the caller block themselves.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from kiro_crew.mcp_caller import CallerContext
from kiro_crew.mcp_gateway import call_gate, folder_scope, hazards, tab_tenancy
from kiro_crew.mcp_gateway.backend_wire import (
    INTERNAL_STUB_PREFIXES,
    _tool_call_error_text,
    _write_json_line,
)

if TYPE_CHECKING:
    from kiro_crew.mcp_gateway.backend import Backend
    from kiro_crew.mcp_gateway.backend_wire import _PendingRequest


@dataclass
class CallerScopeState:
    """What a shared ``Backend`` knows about its callers (one per backend).

    ``tool_scopes`` is learned from the backend's own complete tools/list
    answers (``None`` = never seen, so nothing is scoped); ``stub_sessions`` is
    the attested session each attached stub forwarded for, pruned on detach;
    ``roots_served`` is set once the gateway answered the server's roots/list
    itself and ``roots_answer`` is the folder list last answered or announced;
    ``call_gate`` serializes tools/call (``None`` = off); ``tab_tools`` is the
    (tabs tool, close tool) pair of a browser server and ``tab_active`` each
    caller context's last tab.
    """

    tool_scopes: Optional[dict[str, Any]] = None
    folder_confinable: bool = False
    stub_sessions: dict[str, str] = field(default_factory=dict)
    roots_served: bool = False
    roots_answer: Optional[list[str]] = None
    scope_tasks: set["asyncio.Task[None]"] = field(default_factory=set)
    call_gate: "Optional[call_gate.CallGate]" = None
    tab_tools: Optional[tuple[str, str]] = None
    tab_active: dict[str, int] = field(default_factory=dict)
    #: ``roots/list`` ids the gateway declined to serve, routed the usual way.
    roots_routed: set[Any] = field(default_factory=set)


_STATE_ATTR = "_caller_scope"


def state(self: Backend) -> CallerScopeState:
    """This backend's caller state, made on first use and kept on the instance."""
    found = self.__dict__.get(_STATE_ATTR)
    if not isinstance(found, CallerScopeState):
        found = CallerScopeState()
        self.__dict__[_STATE_ATTR] = found
    return found


logger = logging.getLogger("kiro_crew.mcp_gateway.backend")

_ROOTS_LIST_CHANGED = {"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}


def _adjustable(self: Backend) -> bool:
    return not self.supports_caller_identity


def note_tools_list(self: Backend, pending: "_PendingRequest", msg: dict[str, Any]) -> None:
    """Learn each tool's scope from a complete ``tools/list`` answer on this backend.

    A page of a paginated listing, or an error, leaves the scopes unknown: a
    server whose whole tool set was never seen is not scoped.
    """
    result = msg.get("result")
    if (
        not isinstance(result, dict)
        or pending.list_paginated
        or result.get("nextCursor") is not None
    ):
        return
    tools = result.get("tools")
    if isinstance(tools, list):
        state(self).tool_scopes = folder_scope.scan_tools(tools)
        state(self).folder_confinable = folder_scope.tools_confinable(tools) is True
        if _adjustable(self):
            if state(self).call_gate is None and call_gate.needs_serialization(tools):
                state(self).call_gate = call_gate.CallGate(
                    lambda fid, frame: _gated_write(self, fid, frame)
                )
            state(self).tab_tools = tab_tenancy.find_tabs_tool(tools)
            if tab_tenancy.single_page_browser(tools):
                # No tab to give each chat: every chat gets its own copy. One
                # already shared is recycled, and its stubs respawn privately.
                self._record_hazard(hazards.HAZARD_SINGLE_PAGE_BROWSER, any_client=True)
                if len(_real_stubs(self)) > 1 and not self._dead_reason:
                    reason = "single-page browser server cannot serve several chats; recycling"
                    self._dead_reason = reason
                    task = asyncio.get_running_loop().create_task(
                        self._broadcast_backend_gone(reason)
                    )
                    state(self).scope_tasks.add(task)
                    task.add_done_callback(state(self).scope_tasks.discard)


class _Unwanted(Exception):
    """The call was cancelled, or its chat left, while its tab was prepared."""


def _still_wanted(self: Backend, fid: str, pending: Optional["_PendingRequest"]) -> bool:
    """The call still holds its slot, was not cancelled, and its chat is still here."""
    gate = state(self).call_gate
    return (
        gate is not None
        and gate.wanted(fid)
        and pending is not None
        and not pending.cancelled
        and self._pending_requests.get(fid) is pending
    )


async def _gated_write(self: Backend, fid: str, frame: dict[str, Any]) -> bool:
    """Write one serialized call upstream (``call_gate``), its caller's tab made current first.

    Returns False when nothing was sent: the call was cancelled, its chat left,
    or the gateway answered it. The gate then frees the slot.
    """
    pending = self._pending_requests.get(fid)
    if not _still_wanted(self, fid, pending):
        self._pending_requests.pop(fid, None)
        return False
    assert pending is not None
    if state(self).tab_tools is not None and pending.session_key:
        try:
            prepared = await _prepare_tab(self, fid, frame, pending)
        except _Unwanted:
            self._pending_requests.pop(fid, None)
            return False
        except Exception as exc:
            if not _still_wanted(self, fid, pending):
                self._pending_requests.pop(fid, None)
                return False
            await _answer_locally(
                self, fid, pending, error=f"browser tab could not be prepared: {exc}"
            )
            return False
        if prepared is None:
            return False
        frame = prepared
        if pending.retry_frame is not None:
            # A rehandshake retry re-sends the call as the server received it.
            pending.retry_frame = frame
        if not _still_wanted(self, fid, pending):
            # Cancelled, or its chat left, while the tab was prepared.
            self._pending_requests.pop(fid, None)
            return False
    gate = state(self).call_gate
    if gate is not None:
        # From here a cancel must go upstream: the frame is on its way.
        gate.mark_sending(fid)
    try:
        await _write_json_line(self.stdin, frame)
    except (BrokenPipeError, ConnectionResetError) as exc:
        self._dead_reason = self._dead_reason or f"stdin closed: {exc}"
        raise
    return True


def cancel_gated(self: Backend, fid: str) -> bool:
    """Cancel *fid* at the gate; True when it was never written (no upstream cancel owed)."""
    gate = state(self).call_gate
    if gate is None:
        return False
    outcome = gate.cancel(fid)
    if outcome == call_gate.DROPPED:
        self._pending_requests.pop(fid, None)
    return outcome in (call_gate.DROPPED, call_gate.UNSENT)


_INTERNAL_CALL_TIMEOUT_SECS = 60.0


async def _internal_call(self: Backend, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """One gateway-originated ``tools/call``, run while the caller's slot is held."""
    from kiro_crew.mcp_gateway.backend_mcp_apps import _APPS_STUB_SENTINEL
    from kiro_crew.mcp_gateway.backend_wire import _PendingRequest

    fid = self._next_forward_id()
    fut: "asyncio.Future[dict[str, Any]]" = asyncio.get_running_loop().create_future()
    self._pending_requests[fid] = _PendingRequest(
        stub_uuid=_APPS_STUB_SENTINEL,
        original_id=None,
        method="tools/call",
        # Stamped like every forwarded request: the wedge sweep reads an
        # unset start as a request as old as the host's uptime.
        t_start_ms=time.monotonic() * 1000.0,
        apps_future=fut,
    )
    frame = {
        "jsonrpc": "2.0",
        "id": fid,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    try:
        await _write_json_line(self.stdin, frame)
        reply = await asyncio.wait_for(fut, timeout=_INTERNAL_CALL_TIMEOUT_SECS)
    finally:
        self._pending_requests.pop(fid, None)
    failure = _tool_call_error_text(reply)
    if failure is not None:
        raise RuntimeError(failure)
    return reply


async def _answer_locally(
    self: Backend, fid: str, pending: "_PendingRequest", *, text: str = "", error: str = ""
) -> None:
    """Reply to the caller from the gateway and free the slot; the server never sees the call."""
    self._pending_requests.pop(fid, None)
    content = [{"type": "text", "text": error or text}]
    result: dict[str, Any] = (
        {"content": content, "isError": True} if error else {"content": content}
    )
    try:
        await self._reply_locally(pending.stub_uuid, pending.original_id, result=result)
    finally:
        gate = state(self).call_gate
        if gate is not None:
            gate.release(fid)


async def _prepare_tab(
    self: Backend, fid: str, frame: dict[str, Any], pending: "_PendingRequest"
) -> Optional[dict[str, Any]]:
    """Make the caller's own tab current and map its tab arguments; ``None`` = answered here."""
    tools = state(self).tab_tools
    assert tools is not None
    tabs_tool, close_tool = tools
    session = pending.session_key
    ctx = tab_tenancy.context_name(session)
    listing = tab_tenancy.parse_tabs(
        tab_tenancy.result_text(await _internal_call(self, tabs_tool, {"action": "list"}))
    )
    if not _still_wanted(self, fid, pending):
        raise _Unwanted()
    mine = tab_tenancy.own_tabs(listing, ctx)
    current = next((t for t in listing if t.current), None)
    if current is not None and current.context and current.context != ctx:
        # Remember where the chat that owns the current tab was, before moving off it.
        owner_tabs = tab_tenancy.own_tabs(listing, current.context)
        state(self).tab_active[current.context] = owner_tabs.index(current)
    name = pending.tool_name
    args = dict(pending.tool_arguments or {})
    if close_tool and name == close_tool:
        for tab in sorted(mine, key=lambda t: t.index, reverse=True):
            if not _still_wanted(self, fid, pending):
                raise _Unwanted()
            await _internal_call(self, tabs_tool, {"action": "close", "index": tab.index})
        state(self).tab_active.pop(ctx, None)
        await _answer_locally(
            self, fid, pending, text="### Result\nClosed this chat's browser tabs."
        )
        return None
    if name == tabs_tool:
        action = args.get("action")
        if action == "new":
            args["isolatedContext"] = ctx
            return _with_arguments(frame, args)
        if action in ("select", "close") and "index" in args:
            index = tab_tenancy.map_index(args["index"], mine)
            if index is None:
                await _answer_locally(self, fid, pending, error=f"Tab {args['index']!r} not found")
                return None
            if action == "select":
                state(self).tab_active[ctx] = int(args["index"])
            args["index"] = index
            return _with_arguments(frame, args)
    if not mine:
        await _internal_call(self, tabs_tool, {"action": "new", "isolatedContext": ctx})
        state(self).tab_active[ctx] = 0
        return _with_arguments(frame, args) if name == tabs_tool else frame
    if current is None or current.context != ctx:
        active = min(state(self).tab_active.get(ctx, len(mine) - 1), len(mine) - 1)
        await _internal_call(self, tabs_tool, {"action": "select", "index": mine[active].index})
    return frame


def _with_arguments(frame: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    raw = frame.get("params")
    params: dict[str, Any] = raw if isinstance(raw, dict) else {}
    return {**frame, "params": {**params, "arguments": args}}


def scope_reply(self: Backend, pending: "_PendingRequest", msg: dict[str, Any]) -> dict[str, Any]:
    """A reply as the caller should read it: only its own browser tabs, numbered from 0."""
    if state(self).tab_tools is None or pending.method != "tools/call" or not pending.session_key:
        return msg
    tools = state(self).tab_tools
    return tab_tenancy.rewrite_reply(
        msg,
        tab_tenancy.context_name(pending.session_key),
        whole=tools is not None and pending.tool_name == tools[0],
    )


def carry_call_slot(self: Backend, old_fid: str, pending: "_PendingRequest") -> None:
    """A rehandshake re-sent the call *old_fid*: its retry keeps the serialized slot."""
    gate = state(self).call_gate
    if gate is None or gate.in_flight != old_fid:
        return
    retry = next(
        (
            fid
            for fid, p in self._pending_requests.items()
            if p.stub_uuid == pending.stub_uuid
            and p.original_id == pending.original_id
            and p.method == pending.method
        ),
        None,
    )
    if retry is None:
        gate.release(old_fid)
    else:
        gate.rekey(old_fid, retry)


def end_call(self: Backend, fid: str) -> None:
    """A reply for *fid* arrived: free the serialized slot it held, if any."""
    gate = state(self).call_gate
    if gate is not None:
        gate.release(fid)


def _real_stubs(self: Backend) -> list[str]:
    """The attached stubs that are chats, not the gateway's own internal ones."""
    return [s for s in self._stub_inboxes if not s.startswith(INTERNAL_STUB_PREFIXES)]


def _attached_union(self: Backend) -> Optional[list[str]]:
    keys = [state(self).stub_sessions.get(stub) for stub in _real_stubs(self)]
    if any(not k for k in keys):
        return None
    return folder_scope.union_roots(k for k in keys if k)


async def _send_roots_changed_if_needed(self: Backend) -> None:
    if not state(self).roots_served:
        return
    union = _attached_union(self)
    if union is None or union == state(self).roots_answer:
        return
    # Remembered as announced: the server re-asks and is answered this list.
    state(self).roots_answer = union
    try:
        await _write_json_line(self.stdin, _ROOTS_LIST_CHANGED)
    except (BrokenPipeError, ConnectionResetError, OSError):
        logger.debug("backend pid=%s: roots list_changed not delivered", self.pid)


async def note_caller(self: Backend, stub_uuid: str, caller: Optional[CallerContext]) -> None:
    """Remember which session *stub_uuid* speaks for; tell the server when its roots grew."""
    if not _adjustable(self) or caller is None or not caller.session_key:
        return
    if state(self).stub_sessions.get(stub_uuid) == caller.session_key:
        return
    state(self).stub_sessions[stub_uuid] = caller.session_key
    await _send_roots_changed_if_needed(self)


async def forget_stub(self: Backend, stub_uuid: str) -> None:
    """Drop *stub_uuid*'s session; tell the server when its roots shrank."""
    if state(self).stub_sessions.pop(stub_uuid, None) is not None:
        await _send_roots_changed_if_needed(self)


def scope_forward(
    self: Backend, stub_uuid: str, msg: dict[str, Any], caller: Optional[CallerContext]
) -> dict[str, Any]:
    """*msg* adjusted for *caller*; the forward choke point's single hook. Never raises."""
    if not _adjustable(self) or caller is None or msg.get("method") != "tools/call":
        return msg
    params = msg.get("params")
    if not isinstance(params, dict) or state(self).tool_scopes is None:
        return msg
    name = params.get("name")
    scopes = state(self).tool_scopes
    scope = scopes.get(name) if scopes is not None and isinstance(name, str) else None
    folder = folder_scope.session_folder(caller.session_key)
    arguments = params.get("arguments")
    scoped = folder_scope.scope_arguments(
        arguments, scope, folder, folder_user=state(self).roots_served
    )
    if scoped is arguments:
        return msg
    out = dict(msg)
    out["params"] = {**params, "arguments": scoped}
    return out


async def _learn_tool_scopes(self: Backend) -> None:
    """Ask the backend for its tool list on an internal stub; the answer is harvested."""
    if state(self).tool_scopes is None:
        await self.probe_tool_surface()


def may_serve_roots(self: Backend) -> bool:
    """Cheap pre-check: could :func:`serve_roots` answer now? (No IO, no await.)"""
    return (
        _adjustable(self)
        and _attached_union(self) is not None
        and (state(self).tool_scopes is None or state(self).folder_confinable)
    )


def claim_roots_request(self: Backend, msg: dict[str, Any]) -> bool:
    """Take a server ``roots/list`` to answer it from the gateway. False: route it as before.

    The decision may need the tool list, whose answer the stdout pump has to
    read, so it runs as a task beside the pump; a request it declines is handed
    back to the pump's routing once, marked so it is not claimed again.
    """
    st = state(self)
    msg_id = msg.get("id")
    if msg_id in st.roots_routed:
        st.roots_routed.discard(msg_id)
        return False
    if not may_serve_roots(self):
        return False
    task = asyncio.get_running_loop().create_task(_serve_or_route_roots(self, msg))
    st.scope_tasks.add(task)
    task.add_done_callback(st.scope_tasks.discard)
    return True


async def _serve_or_route_roots(self: Backend, msg: dict[str, Any]) -> None:
    try:
        if await serve_roots(self, msg):
            return
    except Exception:  # pragma: no cover - defensive; fall back to routing
        logger.warning("backend pid=%s: serving roots/list raised", self.pid, exc_info=True)
    state(self).roots_routed.add(msg.get("id"))
    await self._route_backend_message(msg, msg.get("id"), msg.get("method"))


async def serve_roots(self: Backend, msg: dict[str, Any]) -> bool:
    """Answer a server ``roots/list`` with the attached callers' folders. False: not served.

    Served only when every tool can be scoped and every attached caller's
    folder is known; otherwise the caller of this keeps the earlier routing
    (deliver to the one stub, or recycle a shared backend).
    """
    if not may_serve_roots(self):
        return False
    if state(self).tool_scopes is None:
        await _learn_tool_scopes(self)
    if not state(self).folder_confinable:
        return False
    # Read again: a caller may have attached or left while the list was fetched.
    union = _attached_union(self)
    if union is None:
        return False
    reply = {
        "jsonrpc": "2.0",
        "id": msg.get("id"),
        "result": {"roots": [{"uri": folder_scope.file_uri(f)} for f in union]},
    }
    try:
        await _write_json_line(self.stdin, reply)
    except (BrokenPipeError, ConnectionResetError, OSError):
        return True  # the pump reports the dead backend; nothing to route
    first = not state(self).roots_served
    state(self).roots_served = True
    state(self).roots_answer = union
    if first:
        key = self.pool_key
        identity = hazards.launch_identity(
            key.command_args_hash, key.effective_env_hash, key.binary_version
        )
        # The gateway answers this server's roots itself, so the request is not
        # evidence that it must run once per chat.
        hazards.retract_observed(key.server_name, hazards.HAZARD_ROOTS_REQUESTED, identity)
        logger.info(
            "backend pid=%s: gateway answers roots/list for %r with %d folder(s)",
            self.pid,
            key.server_name,
            len(union),
        )
    return True

"""Folder scoping on a shared MCP backend: the caller's folder, path args and roots.

A shared backend runs in one Crew-private folder. These tests pin how the
gateway serves several chats from it (``mcp_gateway.folder_scope`` and
``backend_caller_scope``): relative folder arguments resolve against the
CALLER's folder, a required ``repo_path`` is filled, ``roots/list`` is answered
by the gateway with every attached chat's folder, and a server whose tools
cannot be scoped keeps the routing it had before.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import pytest
from mcp_gateway_backend_coverage_helpers import _no_real_metrics_file  # noqa: F401 -- autouse
from mcp_gateway_backend_coverage_helpers import _frames, _line, _make_backend

from kiro_crew.mcp_caller import CallerContext
from kiro_crew.mcp_gateway import backend_caller_scope as caller_scope
from kiro_crew.mcp_gateway import call_gate, claim, folder_scope, hazards, tab_tenancy
from kiro_crew.mcp_gateway.daemon import control
from kiro_crew.testing.wait import async_wait_until

FS_TOOLS = [
    {
        "name": "read_text_file",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "move_file",
        "inputSchema": {
            "type": "object",
            "properties": {"source": {"type": "string"}, "destination": {"type": "string"}},
        },
    },
]
GIT_TOOL = {
    "name": "git_status",
    "inputSchema": {
        "type": "object",
        "properties": {"repo_path": {"type": "string"}},
        "required": ["repo_path"],
    },
}
SHELL_TOOL = {
    "name": "run",
    "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
}


@pytest.fixture(autouse=True)
def _fresh_folders() -> Any:
    folder_scope.forget_session_folders()
    yield
    folder_scope.forget_session_folders()


def _folders(tmp_path: Path) -> tuple[str, str]:
    a, b = tmp_path / "projA", tmp_path / "projB"
    a.mkdir()
    b.mkdir()
    folder_scope.record_session_folder("chat-a", str(a))
    folder_scope.record_session_folder("chat-b", str(b))
    return str(a), str(b)


# --- pure rules -------------------------------------------------------------


def test_scan_tool_confinable_and_fill() -> None:
    assert folder_scope.scan_tool(FS_TOOLS[0]) == folder_scope.ToolScope(True, ())
    assert folder_scope.scan_tool(GIT_TOOL) == folder_scope.ToolScope(True, ("repo_path",))
    assert folder_scope.scan_tool(SHELL_TOOL).confinable is False
    assert folder_scope.scan_tool({"name": "x"}).confinable is False
    assert folder_scope.tools_confinable(FS_TOOLS + [GIT_TOOL]) is True
    assert folder_scope.tools_confinable(FS_TOOLS + [SHELL_TOOL]) is False
    assert folder_scope.tools_confinable([]) is None


def test_scope_arguments_rewrites_only_what_applies(tmp_path: Path) -> None:
    a, b = _folders(tmp_path)
    git = folder_scope.scan_tool(GIT_TOOL)
    fs = folder_scope.scan_tool(FS_TOOLS[0])
    # A relative folder argument and a missing required one resolve to the caller's folder.
    assert folder_scope.scope_arguments({"repo_path": "."}, git, a, folder_user=False) == {
        "repo_path": a
    }
    assert folder_scope.scope_arguments({}, git, b, folder_user=False) == {"repo_path": b}
    # A plain path is left alone unless the server works on the chat's folder.
    assert folder_scope.scope_arguments({"path": "note.txt"}, fs, a, folder_user=False) == {
        "path": "note.txt"
    }
    assert folder_scope.scope_arguments({"path": "note.txt"}, fs, b, folder_user=True) == {
        "path": os.path.join(b, "note.txt")
    }
    # An absolute path into another chat's folder is not refused: one local user.
    other = os.path.join(a, "secret.txt")
    assert folder_scope.scope_arguments({"path": other}, fs, b, folder_user=True) == {"path": other}
    # Nothing known, nothing changed.
    args = {"path": "x"}
    assert folder_scope.scope_arguments(args, None, a, folder_user=True) is args
    assert folder_scope.scope_arguments(args, fs, "", folder_user=True) is args


def test_only_absolute_folders_are_recorded() -> None:
    assert folder_scope.record_session_folder("s", "relative/dir") is False
    assert folder_scope.record_session_folder("s", 7) is False
    assert folder_scope.union_roots(["s"]) is None


def test_claim_frame_carries_the_session_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claim.platform_compat, "get_process_start_id", lambda pid: None)
    frame = claim.build_claim_frame(4321, "chat-a", None, "tok", "/work/projA")
    assert frame["work_dir"] == "/work/projA"
    assert "work_dir" not in claim.build_claim_frame(4321, "chat-a", None, "tok")


@pytest.mark.asyncio
async def test_apply_claim_records_the_folder(tmp_path: Path) -> None:
    frame = {
        "type": "claim",
        "pid": 4321,
        "caller": {"session_key": "chat-z"},
        "work_dir": str(tmp_path),
    }
    await control._apply_claim(frame)
    assert folder_scope.session_folder("chat-z") == str(tmp_path)


def test_retract_forgets_only_roots_for_one_launch(tmp_path: Path) -> None:
    ledger = hazards.HazardLedger(tmp_path / "h.json")
    ledger.record("fs", hazards.HAZARD_ROOTS_REQUESTED, "id1")
    ledger.record("fs", hazards.HAZARD_ROOTS_REQUESTED, "id2")
    assert ledger.retract("fs", hazards.HAZARD_ROOTS_REQUESTED, "id1") is True
    assert ledger.codes_for("fs", "id1") == ()
    assert ledger.codes_for("fs", "id2") == (hazards.HAZARD_ROOTS_REQUESTED,)
    assert hazards.retract_observed("fs", hazards.HAZARD_UNROUTABLE_SERVER_REQUEST, "id2") is False


# --- the shared backend -----------------------------------------------------


def _caller(key: str) -> CallerContext:
    return CallerContext(session_key=key, from_gateway=True)


async def _two_chats(tmp_path: Path, tools: Any) -> Any:
    a, b = _folders(tmp_path)
    backend = _make_backend()
    inbox_a = await backend.attach_stub("stub-a")
    inbox_b = await backend.attach_stub("stub-b")
    await caller_scope.note_caller(backend, "stub-a", _caller("chat-a"))
    await caller_scope.note_caller(backend, "stub-b", _caller("chat-b"))
    if tools is not None:
        caller_scope.note_tools_list(
            backend, backend_pending("tools/list"), {"result": {"tools": tools}}
        )
    return backend, inbox_a, inbox_b, a, b


def backend_pending(method: str) -> Any:
    from kiro_crew.mcp_gateway.backend import _PendingRequest

    return _PendingRequest(stub_uuid="stub-a", original_id=1, method=method)


def _roots_answers(backend: Any) -> list[dict]:
    return [f for f in _frames(backend) if f.get("id") == "srv-roots" and "result" in f]


@pytest.mark.asyncio
async def test_gateway_answers_roots_with_every_chats_folder(tmp_path: Path) -> None:
    backend, inbox_a, inbox_b, a, b = await _two_chats(tmp_path, FS_TOOLS)
    await backend._route_backend_line(_line({"id": "srv-roots", "method": "roots/list"}))
    await async_wait_until(lambda: _roots_answers(backend), timeout=5)
    roots = _roots_answers(backend)[0]["result"]["roots"]
    assert [r["uri"] for r in roots] == [Path(a).as_uri(), Path(b).as_uri()]
    # Not routed to a chat, not recycled, and not recorded as per-chat evidence.
    assert inbox_a.empty() and inbox_b.empty()
    assert backend.dead_reason is None
    assert caller_scope.state(backend).roots_served is True


@pytest.mark.asyncio
async def test_unknown_tools_are_listed_before_roots_are_answered(tmp_path: Path) -> None:
    backend, _a, _b, _fa, _fb = await _two_chats(tmp_path, None)
    await backend._route_backend_line(_line({"id": "srv-roots", "method": "roots/list"}))

    def _listing() -> Any:
        return next((f for f in _frames(backend) if f.get("method") == "tools/list"), None)

    await async_wait_until(lambda: _listing() is not None, timeout=5)
    await backend._route_backend_line(
        _line({"id": _listing()["id"], "result": {"tools": FS_TOOLS}})
    )
    await async_wait_until(lambda: _roots_answers(backend), timeout=5)
    assert caller_scope.state(backend).folder_confinable is True


@pytest.mark.asyncio
async def test_unconfinable_server_keeps_per_chat_routing(tmp_path: Path) -> None:
    backend, *_ = await _two_chats(tmp_path, FS_TOOLS + [SHELL_TOOL])
    await backend._route_backend_line(_line({"id": "srv-roots", "method": "roots/list"}))
    assert _roots_answers(backend) == []
    assert "cannot route without a cross-tenant leak" in (backend.dead_reason or "")


@pytest.mark.asyncio
async def test_unknown_folder_keeps_the_old_routing(tmp_path: Path) -> None:
    backend = _make_backend()
    inbox = await backend.attach_stub("stub-x")
    await caller_scope.note_caller(backend, "stub-x", _caller("chat-without-folder"))
    await backend._route_backend_line(_line({"id": "srv-roots", "method": "roots/list"}))
    assert (await_json(inbox))["method"] == "roots/list"


def await_json(inbox: Any) -> dict:
    import json

    return json.loads(inbox.get_nowait().decode("utf-8"))


@pytest.mark.asyncio
async def test_roots_change_is_announced_on_attach_and_detach(tmp_path: Path) -> None:
    backend, *_rest, a, b = await _two_chats(tmp_path, FS_TOOLS)
    await backend._route_backend_line(_line({"id": "srv-roots", "method": "roots/list"}))
    await async_wait_until(lambda: _roots_answers(backend), timeout=5)

    def _changes() -> int:
        return sum(
            1 for f in _frames(backend) if f.get("method") == "notifications/roots/list_changed"
        )

    c = tmp_path / "projC"
    c.mkdir()
    folder_scope.record_session_folder("chat-c", str(c))
    await backend.attach_stub("stub-c")
    await caller_scope.note_caller(backend, "stub-c", _caller("chat-c"))
    assert _changes() == 1
    await backend.detach_stub("stub-a")
    assert _changes() == 2
    # A second chat in a folder already served changes nothing.
    await backend.attach_stub("stub-b2")
    await caller_scope.note_caller(backend, "stub-b2", _caller("chat-b"))
    assert _changes() == 2


@pytest.mark.asyncio
async def test_relative_path_reaches_the_server_as_the_callers_file(tmp_path: Path) -> None:
    backend, _a, _b, a, b = await _two_chats(tmp_path, FS_TOOLS + [GIT_TOOL])
    caller_scope.state(backend).roots_served = True
    call = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "read_text_file", "arguments": {"path": "note.txt"}},
    }
    await backend.forward_from_stub("stub-b", call, caller=_caller("chat-b"))
    git = {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "git_status"}}
    await backend.forward_from_stub("stub-a", git, caller=_caller("chat-a"))

    def _sent() -> list[dict]:
        return [f for f in _frames(backend) if f.get("method") == "tools/call"]

    # Serialized (these tools are not read-only): the second goes once the first is answered.
    await async_wait_until(lambda: len(_sent()) == 1, timeout=5)
    await backend._route_backend_line(_line({"id": _sent()[0]["id"], "result": {"content": []}}))
    await async_wait_until(lambda: len(_sent()) == 2, timeout=5)
    sent = _sent()
    assert sent[0]["params"]["arguments"] == {"path": os.path.join(b, "note.txt")}
    assert sent[1]["params"]["arguments"] == {"repo_path": a}


@pytest.mark.asyncio
async def test_crews_own_servers_are_never_rewritten(tmp_path: Path) -> None:
    backend, _a, _b, _fa, _fb = await _two_chats(tmp_path, [GIT_TOOL])
    backend.supports_caller_identity = True
    call = {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "git_status"}}
    assert caller_scope.scope_forward(backend, "stub-a", call, _caller("chat-a")) is call


# --- serialized calls (call_gate) ---------------------------------------------


def test_needs_serialization_only_without_read_only_hints() -> None:
    ro = {"name": "r", "annotations": {"readOnlyHint": True}}
    assert call_gate.needs_serialization([ro]) is False
    assert call_gate.needs_serialization([ro, {"name": "w"}]) is True
    assert call_gate.needs_serialization([]) is False


@pytest.mark.asyncio
async def test_gate_writes_one_call_at_a_time_and_drops_queued_cancels() -> None:
    written: list[str] = []

    async def write(fid: str, frame: dict) -> bool:
        written.append(fid)
        return True

    gate = call_gate.CallGate(write)
    for fid in ("f1", "f2", "f3"):
        gate.submit(fid, {"id": fid})
    await async_wait_until(lambda: written == ["f1"], timeout=5)
    assert gate.cancel("f2") == call_gate.DROPPED
    gate.release("f1")
    await async_wait_until(lambda: written == ["f1", "f3"], timeout=5)
    gate.fail_all()
    assert gate.in_flight is None and gate.queued() == []


@pytest.mark.asyncio
async def test_cancelled_in_flight_call_frees_the_slot_after_grace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(call_gate, "CANCEL_GRACE_SECS", 0.01)
    written: list[str] = []

    async def write(fid: str, frame: dict) -> bool:
        written.append(fid)
        return True

    gate = call_gate.CallGate(write)
    gate.submit("f1", {})
    gate.submit("f2", {})
    await async_wait_until(lambda: written == ["f1"], timeout=5)
    assert gate.cancel("f1") == call_gate.SENT
    await async_wait_until(lambda: written == ["f1", "f2"], timeout=5)


@pytest.mark.asyncio
async def test_parallel_writes_reach_a_stateful_server_one_by_one(tmp_path: Path) -> None:
    backend, *_ = await _two_chats(tmp_path, [{"name": "create_entities", "inputSchema": {}}])

    def _calls() -> list[dict]:
        return [f for f in _frames(backend) if f.get("method") == "tools/call"]

    for i in range(40):
        stub, chat = ("stub-a", "chat-a") if i % 2 else ("stub-b", "chat-b")
        frame = {
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/call",
            "params": {"name": "create_entities"},
        }
        await backend.forward_from_stub(stub, frame, caller=_caller(chat))
    for n in range(1, 41):
        # Never more than one call written ahead of the replies.
        await async_wait_until(lambda n=n: len(_calls()) == n, timeout=5)
        await backend._route_backend_line(_line({"id": _calls()[-1]["id"], "result": {}}))
    assert len(_calls()) == 40


@pytest.mark.asyncio
async def test_a_queued_call_cancelled_never_reaches_the_server(tmp_path: Path) -> None:
    backend, inbox_a, *_ = await _two_chats(tmp_path, [{"name": "w", "inputSchema": {}}])
    for i in (1, 2):
        frame = {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "w"}}
        await backend.forward_from_stub("stub-a", frame, caller=_caller("chat-a"))
    cancel = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}}
    await backend.forward_from_stub("stub-a", cancel, caller=_caller("chat-a"))

    def _calls() -> list[dict]:
        return [f for f in _frames(backend) if f.get("method") == "tools/call"]

    await async_wait_until(lambda: len(_calls()) == 1, timeout=5)
    await backend._route_backend_line(_line({"id": _calls()[0]["id"], "result": {}}))
    assert (
        caller_scope.state(backend).call_gate.in_flight is None
        and caller_scope.state(backend).call_gate.queued() == []
    )
    assert len(_calls()) == 1
    assert not any(f.get("method") == "notifications/cancelled" for f in _frames(backend))


# --- a browser tab per caller (tab_tenancy) ---------------------------------

PW_TABS = {
    "name": "browser_tabs",
    "inputSchema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["list", "new", "close", "select"]},
            "index": {"type": "number"},
            "isolatedContext": {"type": "string"},
        },
    },
}


def test_tabs_tool_found_by_shape() -> None:
    close = {"name": "browser_close", "inputSchema": {"type": "object", "properties": {}}}
    assert tab_tenancy.find_tabs_tool([PW_TABS, close]) == ("browser_tabs", "browser_close")
    plain = {"name": "tabs", "inputSchema": {"properties": {"action": {"enum": ["list"]}}}}
    assert tab_tenancy.find_tabs_tool([plain]) is None


def test_listing_is_limited_to_the_callers_tabs() -> None:
    a, b = tab_tenancy.context_name("chat-a"), tab_tenancy.context_name("chat-b")
    text = (
        "### Open tabs\n"
        f"- 0: [A](http://x/a) [isolatedContext: {a}]\n"
        f"- 1: (current) [B](http://x/b) [isolatedContext: {b}]\n"
        f"- 2: [A2](http://x/a2) [isolatedContext: {a}]\n"
        "### Page"
    )
    tabs = tab_tenancy.parse_tabs(text)
    assert [t.index for t in tab_tenancy.own_tabs(tabs, a)] == [0, 2]
    assert tab_tenancy.map_index(1, tab_tenancy.own_tabs(tabs, a)) == 2
    assert tab_tenancy.map_index(2, tab_tenancy.own_tabs(tabs, a)) is None
    assert tab_tenancy.rewrite_listing(text, b) == (
        f"### Open tabs\n- 0: (current) [B](http://x/b) [isolatedContext: {b}]\n### Page"
    )
    reply = {"result": {"content": [{"type": "text", "text": text}]}}
    out = tab_tenancy.rewrite_reply(reply, a)["result"]["content"][0]["text"]
    assert "[B]" not in out and "- 1: [A2]" in out


@pytest.mark.asyncio
async def test_a_departed_chats_call_in_flight_frees_the_slot_after_grace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(call_gate, "CANCEL_GRACE_SECS", 0.01)
    backend, *_ = await _two_chats(tmp_path, [{"name": "w", "inputSchema": {}}])

    def _calls() -> list[dict]:
        return [f for f in _frames(backend) if f.get("method") == "tools/call"]

    for stub, chat, i in (("stub-a", "chat-a", 1), ("stub-b", "chat-b", 2)):
        frame = {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "w"}}
        await backend.forward_from_stub(stub, frame, caller=_caller(chat))
    await async_wait_until(lambda: len(_calls()) == 1, timeout=5)
    # The chat stops: its call is cancelled upstream and gets no reply.
    await backend.cancel_in_flight_for_stub("stub-a")
    await backend.detach_stub("stub-a")
    await async_wait_until(lambda: len(_calls()) == 2, timeout=5)


@pytest.mark.asyncio
async def test_a_call_cancelled_before_it_is_written_is_never_sent(tmp_path: Path) -> None:
    backend, *_ = await _two_chats(tmp_path, [{"name": "w", "inputSchema": {}}])
    gate = caller_scope.state(backend).call_gate
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "w"}}
    await backend.forward_from_stub("stub-a", frame, caller=_caller("chat-a"))
    fid = gate.in_flight
    backend._pending_requests[fid].cancelled = True
    await async_wait_until(lambda: gate.in_flight is None, timeout=5)
    assert not [f for f in _frames(backend) if f.get("method") == "tools/call"]


@pytest.mark.asyncio
async def test_a_stop_while_the_tab_is_prepared_never_sends_the_call(tmp_path: Path) -> None:
    """Stop/disconnect (``cancel_in_flight_for_stub`` + detach) during preparation."""
    backend, *_ = await _two_chats(tmp_path, [PW_TABS, {"name": "browser_navigate"}])
    gate = caller_scope.state(backend).call_gate
    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "browser_navigate", "arguments": {"url": "http://x"}},
    }
    await backend.forward_from_stub("stub-a", frame, caller=_caller("chat-a"))

    def _listing() -> Any:
        return next(
            (f for f in _frames(backend) if f.get("params", {}).get("name") == "browser_tabs"),
            None,
        )

    # The gateway is preparing chat A's tab (its tab listing is out, unanswered).
    await async_wait_until(lambda: _listing() is not None, timeout=5)
    await backend.cancel_in_flight_for_stub("stub-a")
    await backend.detach_stub("stub-a")
    await backend._route_backend_line(
        _line({"id": _listing()["id"], "result": {"content": [{"type": "text", "text": ""}]}})
    )
    await async_wait_until(lambda: gate.in_flight is None, timeout=5)
    names = [f.get("params", {}).get("name") for f in _frames(backend)]
    assert "browser_navigate" not in names
    assert not any(f.get("method") == "notifications/cancelled" for f in _frames(backend))


@pytest.mark.asyncio
async def test_a_failed_internal_tab_call_fails_the_callers_call(tmp_path: Path) -> None:
    backend, inbox_a, *_ = await _two_chats(tmp_path, [PW_TABS, {"name": "browser_close"}])
    frame = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "browser_close"}}
    await backend.forward_from_stub("stub-a", frame, caller=_caller("chat-a"))

    def _listing() -> Any:
        return next(
            (f for f in _frames(backend) if f.get("params", {}).get("name") == "browser_tabs"),
            None,
        )

    await async_wait_until(lambda: _listing() is not None, timeout=5)
    failed = {"content": [{"type": "text", "text": "boom"}], "isError": True}
    await backend._route_backend_line(_line({"id": _listing()["id"], "result": failed}))
    await async_wait_until(lambda: not inbox_a.empty(), timeout=5)
    reply = await_json(inbox_a)
    assert reply["id"] == 7 and reply["result"]["isError"] is True


@pytest.mark.asyncio
async def test_a_cancel_once_the_frame_is_going_out_is_sent_upstream() -> None:
    async def write(fid: str, frame: dict) -> bool:
        return True

    gate = call_gate.CallGate(write)
    gate.submit("f1", {})
    gate.mark_sending("f1")
    assert gate.cancel("f1") == call_gate.SENT
    gate.fail_all()


def test_a_single_page_browser_is_recorded_so_the_next_chat_gets_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hazards, "_sink", hazards.HazardLedger(tmp_path / "h.json"))
    navigate = {
        "name": "puppeteer_navigate",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
    }
    assert tab_tenancy.single_page_browser([navigate]) is True
    assert tab_tenancy.single_page_browser([navigate, PW_TABS]) is False
    backend = _make_backend()
    caller_scope.note_tools_list(
        backend, backend_pending("tools/list"), {"result": {"tools": [navigate]}}
    )
    key = backend.pool_key
    identity = hazards.launch_identity(
        key.command_args_hash, key.effective_env_hash, key.binary_version
    )
    assert hazards.retreat_codes(key.server_name, identity) == (hazards.HAZARD_SINGLE_PAGE_BROWSER,)


@pytest.mark.asyncio
async def test_the_gateways_own_tab_call_carries_a_start_time(tmp_path: Path) -> None:
    backend, *_ = await _two_chats(tmp_path, [PW_TABS, {"name": "browser_navigate"}])
    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "browser_navigate"},
    }
    await backend.forward_from_stub("stub-a", frame, caller=_caller("chat-a"))

    def _internal() -> Any:
        return next(
            (p for p in backend._pending_requests.values() if p.original_id is None),
            None,
        )

    await async_wait_until(lambda: _internal() is not None, timeout=5)
    assert _internal().t_start_ms > 0
    gate = caller_scope.state(backend).call_gate
    task = gate._task
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_a_repository_name_is_never_taken_for_a_folder(tmp_path: Path) -> None:
    a, _b = _folders(tmp_path)
    github = {
        "name": "get_file_contents",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner", "repo"],
        },
    }
    scope = folder_scope.scan_tool(github)
    args = {"owner": "kirodotdev", "repo": "KiroCrew"}
    assert folder_scope.scope_arguments(dict(args), scope, a, folder_user=False) == args
    assert folder_scope.scope_arguments({"owner": "x"}, scope, a, folder_user=False) == {
        "owner": "x"
    }


def test_page_content_shaped_like_a_tab_line_is_kept() -> None:
    a = tab_tenancy.context_name("chat-a")
    text = "### Result\n- 0: [Other](http://x/o)\n### Open tabs\n- 0: [Other](http://x/o)"
    out = tab_tenancy.rewrite_listing(text, a)
    assert out == "### Result\n- 0: [Other](http://x/o)\n### Open tabs"
    assert tab_tenancy.rewrite_listing(text, a, whole=True) == "### Result\n### Open tabs"


@pytest.mark.asyncio
async def test_a_shared_single_page_browser_is_recycled_at_once(tmp_path: Path) -> None:
    navigate = {
        "name": "puppeteer_navigate",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
    }
    backend, *_ = await _two_chats(tmp_path, [navigate])
    assert backend.dead_reason is not None and "single-page browser" in backend.dead_reason
    await asyncio.gather(*list(caller_scope.state(backend).scope_tasks))

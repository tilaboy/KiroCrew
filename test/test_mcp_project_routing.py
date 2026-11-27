"""The callers of per-project MCP backends: the sender, the routing and the target.

``daemon.project_scope`` keys and confines a per-project backend by a session
record only the owner sends. These tests pin the three callers: the gateway sends
that record next to the claim, the rewriter turns a server not known to be
folder-free into a ``--project-scoped`` stub, and the daemon resolves such a
stub's target without a launch approval while every other key keeps it.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest
from mcp_launch_approval_helpers import (
    _APPROVED_CMD,
    _approval_module,
    _pool_key,
    _target_spec,
)

from kiro_crew.mcp_gateway import claim
from kiro_crew.mcp_gateway.folder_use import FolderDeclarations, ProjectRouting
from kiro_crew.mcp_gateway.hashing import (
    PROJECT_SCOPED_FLAG,
    PROJECT_TARGET_PREFIX,
    expand_stub_flags,
)

#: Opts this module out of the conftest fixture that approves every gatewayd launch.
ENFORCE_LAUNCH_APPROVAL = True


# --------------------------------------------------------------------------- #
# Sender
# --------------------------------------------------------------------------- #


def test_the_frame_names_the_git_toplevel_of_a_subdirectory(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    sub = repo / "pkg" / "src"
    sub.mkdir(parents=True)

    frame = claim.build_session_project_frame(
        "dashboard:s1", str(sub), "standard", ("/h/.aws",), ("/h/.gitconfig",)
    )

    assert frame == {
        "type": "session-project",
        "session_key": "dashboard:s1",
        "root": str(repo),
        "sandbox_mode": "standard",
        "hidden_dirs": ["/h/.aws"],
        "expose_files": ["/h/.gitconfig"],
    }


def test_a_worktree_git_file_is_its_own_project(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    worktree = tmp_path / "wt"
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: ../.git/worktrees/wt\n")

    (worktree / "a").mkdir()

    assert claim.project_root(str(worktree / "a")) == str(worktree)


def test_a_folder_outside_any_repository_is_its_own_root(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()

    frame = claim.build_session_project_frame("k", str(plain), "auto")

    assert frame is not None and frame["root"] == str(plain)


@pytest.mark.parametrize("mode", ["off", ""])
def test_a_session_with_no_sandbox_sends_nothing(tmp_path: Path, mode: str) -> None:
    assert claim.build_session_project_frame("k", str(tmp_path), mode) is None


def test_a_warm_session_is_named_by_its_token_and_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kiro_crew import platform_compat

    monkeypatch.setattr(platform_compat, "get_process_start_id", lambda pid: f"start-{pid}")

    frame = claim.build_session_project_frame(
        "", str(tmp_path), "standard", stub_session_token="tok", pid=4242
    )

    assert frame is not None and "session_key" not in frame
    assert (frame["stub_session_token"], frame["pid"], frame["pid_start_id"]) == (
        "tok",
        4242,
        "start-4242",
    )
    # Neither a key nor a token and runtime: nothing names the session.
    assert claim.build_session_project_frame("", str(tmp_path), "standard") is None
    assert (
        claim.build_session_project_frame("", str(tmp_path), "standard", stub_session_token="tok")
        is None
    )


@pytest.mark.asyncio
async def test_a_warm_session_sends_its_record_but_no_claim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import kiro_crew.acp.runtime as rt_mod
    from kiro_crew.acp.runtime import AcpRuntime

    sent: list[Any] = []

    async def _claim(*a: Any) -> bool:
        sent.append(("claim", a))
        return True

    async def _project(socket_path: str, frame: dict) -> bool:
        sent.append(("project", frame))
        return True

    monkeypatch.setattr(rt_mod, "send_claim", _claim)
    monkeypatch.setattr(rt_mod, "send_session_project", _project)
    monkeypatch.setattr(rt_mod, "publish_session_token", lambda *_a: None)
    runtime = AcpRuntime(work_dir=str(tmp_path))
    runtime._mcp_gateway_socket = "/tmp/kirocrew-gw.sock"
    runtime._sandbox_mode = "standard"
    monkeypatch.setattr(type(runtime), "pid", property(lambda _self: 4242))

    _entries, token = await runtime._own_stub_session(
        [{"name": "one", "command": "python", "args": [], "env": []}], "", tmp_path
    )

    assert [kind for kind, _ in sent] == ["project"]
    frame = sent[0][1]
    assert (frame["stub_session_token"], frame["pid"], frame["root"]) == (
        token,
        4242,
        str(tmp_path),
    )


@pytest.mark.asyncio
async def test_the_record_goes_out_with_the_claim_before_session_new(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import kiro_crew.acp.runtime as rt_mod
    from kiro_crew.acp.runtime import AcpRuntime

    sent: list[Any] = []

    async def _claim(*a: Any) -> bool:
        sent.append(("claim", a[2]))
        return True

    async def _project(socket_path: str, frame: dict) -> bool:
        sent.append(("project", frame))
        return True

    monkeypatch.setattr(rt_mod, "send_claim", _claim)
    monkeypatch.setattr(rt_mod, "send_session_project", _project)
    monkeypatch.setattr(rt_mod, "publish_session_token", lambda *_a: None)
    runtime = AcpRuntime(work_dir=str(tmp_path))
    runtime._mcp_gateway_socket = "/tmp/kirocrew-gw.sock"
    runtime._sandbox_mode = "standard"
    runtime._sandbox_hidden_dirs = ("/h/.aws",)
    runtime._sandbox_expose_files = ("/h/.gitconfig",)
    monkeypatch.setattr(type(runtime), "pid", property(lambda _self: 4242))

    await runtime._own_stub_session(
        [{"name": "one", "command": "python", "args": [], "env": []}], "k1", tmp_path
    )

    assert ("claim", "k1") in sent
    project = [entry[1] for entry in sent if entry[0] == "project"]
    assert project and project[0]["root"] == str(tmp_path)
    assert project[0]["sandbox_mode"] == "standard"
    assert project[0]["hidden_dirs"] == ["/h/.aws"]
    assert project[0]["expose_files"] == ["/h/.gitconfig"]


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #


def _routing(**kw: Any) -> ProjectRouting:
    base: dict[str, Any] = {
        "edition": frozenset(),
        "answers": {},
        "bindings": {},
        "observed_roots": frozenset(),
        "dont_share": frozenset(),
        "declarations": FolderDeclarations(),
    }
    base.update(kw)
    return ProjectRouting(**base)


def test_only_a_server_not_known_to_be_folder_free_is_per_project() -> None:
    assert _routing().per_project("files")
    assert _routing(answers={"files": "uses_cwd"}).per_project("files")
    assert not _routing(answers={"files": "not_used"}).per_project("files")
    assert not _routing(edition=frozenset({"files"})).per_project("files")
    assert not _routing().per_project("kirocrew-core")
    assert not _routing(dont_share=frozenset({"files"})).per_project("files")
    assert not _routing(declarations=FolderDeclarations(vault={"files"})).per_project("files")
    assert not _routing(declarations=FolderDeclarations(complete=False)).per_project("files")


def _rewrite(tmp_path: Path, routing: ProjectRouting, stub_servers: frozenset[str] = frozenset()):
    from kiro_crew.mcp_gateway import rewriter

    spec = {
        "name": "agent",
        "mcpServers": {"files": {"command": _APPROVED_CMD, "args": ["--stdio"]}},
        "tools": ["*"],
    }
    result, wrapped = rewriter._rewrite_single_spec(
        spec,
        stubs_dir=tmp_path / "stubs",
        socket_path=tmp_path / "gw.sock",
        work_dir=tmp_path / "wd",
        sandbox_mode="auto",
        approval_mode="interactive",
        stub_servers=stub_servers,
        project_routing=routing,
    )
    targets: dict[str, str] = {}
    rewriter._collect_target_env(result["mcpServers"], targets)
    return result["mcpServers"]["files"], wrapped, targets


def test_a_folder_reading_server_becomes_a_project_scoped_stub(tmp_path: Path) -> None:
    entry, wrapped, targets = _rewrite(tmp_path, _routing())

    assert wrapped == 1
    flags = expand_stub_flags(entry["args"])
    assert PROJECT_SCOPED_FLAG in flags and "--poolable" in flags
    assert targets and all(key.startswith(PROJECT_TARGET_PREFIX) for key in targets)


def test_a_dont_share_server_stays_unwrapped(tmp_path: Path) -> None:
    entry, wrapped, targets = _rewrite(tmp_path, _routing(dont_share=frozenset({"files"})))

    assert wrapped == 0
    assert entry == {"command": _APPROVED_CMD, "args": ["--stdio"]}
    assert targets == {}


def test_a_folder_free_server_keeps_the_one_shared_stub(tmp_path: Path) -> None:
    entry, wrapped, targets = _rewrite(
        tmp_path, _routing(edition=frozenset({"files"})), stub_servers=frozenset({"files"})
    )

    assert wrapped == 1
    assert PROJECT_SCOPED_FLAG not in expand_stub_flags(entry["args"])
    assert targets and not any(key.startswith(PROJECT_TARGET_PREFIX) for key in targets)


@pytest.mark.parametrize("project_backends", [True, False])
def test_the_gateway_pass_routes_projects_only_when_asked(
    tmp_path: Path, project_backends: bool
) -> None:
    import json

    from kiro_crew.mcp_gateway import rewriter

    agents = tmp_path / "agents"
    agents.mkdir()
    (agents / "a.json").write_text(
        json.dumps(
            {
                "name": "a",
                "tools": ["*"],
                "mcpServers": {"files": {"command": _APPROVED_CMD, "args": []}},
            }
        )
    )

    _results, target_env = rewriter.rewrite_agents(
        source_dir=agents,
        overlay_dir=tmp_path / "home" / "mcp-gateway" / "agents",
        socket_path=tmp_path / "gw.sock",
        work_dir=tmp_path / "work",
        stub_servers=frozenset(),
        project_backends=project_backends,
    )

    assert bool(target_env) is project_backends
    assert all(key.startswith(PROJECT_TARGET_PREFIX) for key in target_env)


# --------------------------------------------------------------------------- #
# Target resolution
# --------------------------------------------------------------------------- #


@pytest.fixture
def no_approvals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty approval store and a workspace root this test owns."""
    mod = _approval_module()
    assert mod is not None
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("KIROCREW_WORKSPACE", str(tmp_path / "workspace"))
    (tmp_path / "workspace" / "_default").mkdir(parents=True)
    monkeypatch.setenv(PROJECT_TARGET_PREFIX + "SRV", _target_spec(_APPROVED_CMD))
    monkeypatch.setenv("KIROCREW_MCP_TARGET_SRV", _target_spec(_APPROVED_CMD))


def test_a_project_key_resolves_its_target_without_an_approval(no_approvals: None) -> None:
    from kiro_crew.mcp_gateway import gatewayd

    key = dataclasses.replace(_pool_key("srv"), sandbox_hash="a" * 64)

    target = gatewayd.env_target_resolver(key)

    assert target is not None and target[0] == _APPROVED_CMD


def test_any_other_key_still_needs_an_approval(no_approvals: None) -> None:
    from kiro_crew.mcp_gateway import gatewayd

    assert gatewayd.env_target_resolver(_pool_key("srv")) is None


def test_a_shared_key_never_reads_the_per_project_map(
    no_approvals: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kiro_crew.mcp_gateway.daemon.launch import _target_spec as daemon_target_spec

    monkeypatch.delenv("KIROCREW_MCP_TARGET_SRV")

    assert daemon_target_spec(_pool_key("srv")) == ""


def test_the_gateway_keeps_project_targets_and_drops_unapproved_shared_ones() -> None:
    from kiro_crew.mcp_gateway.launch_approval import LaunchApprovals, filter_target_env

    spec = _target_spec(_APPROVED_CMD)
    kept, dropped = filter_target_env(
        {
            PROJECT_TARGET_PREFIX + "SRV": spec,
            PROJECT_TARGET_PREFIX + "CREDS_AGENT": spec,
            "KIROCREW_MCP_TARGET_SRV": spec,
        },
        LaunchApprovals(),
    )

    assert kept == {PROJECT_TARGET_PREFIX + "SRV": spec}
    assert "SRV" in dropped

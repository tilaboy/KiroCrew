"""Every stdio MCP server is shared and its launch approved with no step for the person.

A fresh install's gateway start stubs a declared stdio server
(``mcp_gateway.auto_share``) and its rewrite pass approves the launch the first
time it sees it (``LaunchApprovals.auto``), so the server runs shared with no
card, dialog or click. Changed args are approved again on the next start, and
the launch they replaced is retired. Left per chat with no step: a server whose
args name the chat's folder, a disabled one, a never-pooled one, Kiro Crew's own and a
remote one.
A person's off is kept through every later start, and sharing turned off skips
the pass. A pass without ``auto`` (not the gateway start's) still refuses.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_launch_approval_helpers import (  # noqa: F401 -- the fixture is requested by name
    _APPROVED_CMD,
    _approval_module,
    _declare,
    _targets_running,
    toggle_home_fixture,
)

from kiro_crew.mcp_gateway import auto_share, folder_use, rewriter

#: Opts this module out of the conftest fixtures that approve every launch and
#: turn this pass off.
ENFORCE_LAUNCH_APPROVAL = True
AUTO_SHARE = True


def _boot(tmp_path: Path, agents: Path, stubs: frozenset[str], *, auto: bool = True):
    """One gateway start's rewrite pass and its save, as ``_init_mcp_gateway`` runs them."""
    mod = _approval_module()
    approvals = mod.load_approvals()
    approvals.auto = auto
    _results, target_env = rewriter.rewrite_agents(
        source_dir=agents,
        overlay_dir=tmp_path / "boot" / "mcp-gateway" / "agents",
        socket_path=tmp_path / "gw.sock",
        work_dir=tmp_path / "work",
        stub_servers=stubs,
        approvals=approvals,
    )
    mod.save_pass(approvals)
    return target_env, approvals


def _config(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "config.json").read_text())


def _agents(agents: Path, **specs: dict) -> None:
    """One agent spec per keyword, each declaring the given ``mcpServers``."""
    for path in agents.glob("*.json"):
        path.unlink()
    for agent, servers in specs.items():
        (agents / f"{agent}.json").write_text(
            json.dumps({"name": agent, "tools": ["*"], "mcpServers": servers})
        )


def test_a_fresh_install_shares_a_stdio_server_with_no_step(tmp_path, toggle_home):
    _declare(toggle_home, "agent spec", _APPROVED_CMD, [])

    assert auto_share.share_declared_servers() == ["srv"]
    assert _config(tmp_path)["mcp_gateway"]["stub_overrides"] == {"srv": True}

    target_env, approvals = _boot(tmp_path, toggle_home, frozenset({"srv"}))
    assert _targets_running(target_env, _APPROVED_CMD)
    assert approvals.refused == {}
    assert set(_approval_module().load_approvals().approved) == {"SRV"}


def test_changed_args_are_approved_again_and_the_old_launch_retired(tmp_path, toggle_home):
    mod = _approval_module()
    _declare(toggle_home, "agent spec", _APPROVED_CMD, [])
    _boot(tmp_path, toggle_home, frozenset({"srv"}))
    first = set(mod.load_approvals().approved["SRV"])

    _declare(toggle_home, "agent spec", _APPROVED_CMD, ["-c", "pass"])
    target_env, approvals = _boot(tmp_path, toggle_home, frozenset({"srv"}))

    assert _targets_running(target_env, _APPROVED_CMD)
    assert approvals.refused == {}
    now = mod.load_approvals().approved["SRV"]
    assert len(now) == 1 and now != first


def test_a_pass_without_auto_still_refuses_a_new_launch(tmp_path, toggle_home):
    """The dashboard's resolution and the app-refresh probe run without ``auto``."""
    _declare(toggle_home, "agent spec", _APPROVED_CMD, [])

    target_env, approvals = _boot(tmp_path, toggle_home, frozenset({"srv"}), auto=False)

    assert _targets_running(target_env, _APPROVED_CMD) == []
    assert approvals.refused == {"SRV": _approval_module().REFUSED_UNAPPROVED}


def test_folder_users_disabled_never_pooled_and_remote_servers_stay_per_chat(toggle_home):
    weather = {"command": "npx", "args": ["-y", "@acme/weather-mcp"]}
    _agents(
        toggle_home,
        a={
            "shared": weather,
            # Folder-free here, but another agent runs it on the chat's folder.
            "fs": {"command": "npx", "args": ["-y", "@acme/fs-mcp", "/data"]},
            "placeholder": {"command": "git-mcp", "env": {"REPO": "${workspaceFolder}"}},
            "off": {"command": "npx", "disabled": True},
            "creds-agent": {"command": "creds-agent"},
            "kirocrew-secrets": {"command": "kirocrew", "args": ["mcp", "secrets"]},
            "remote": {"url": "https://mcp.example.com/sse"},
        },
        b={
            "fs": {"command": "npx", "args": ["-y", "@acme/fs-mcp", "."]},
            # Declared only by a second agent: still shared.
            "only-b": weather,
        },
    )

    assert auto_share.share_declared_servers() == ["only-b", "shared"]


def test_a_persons_off_survives_every_later_start_under_either_spelling(tmp_path, toggle_home):
    _agents(
        toggle_home,
        a={
            "srv": {"command": _APPROVED_CMD},
            "playwright-mcp": {"command": "npx", "args": ["-y", "@playwright/mcp"]},
        },
    )
    off = {"srv": False, "npm:@playwright/mcp": False}
    (tmp_path / "config.json").write_text(json.dumps({"mcp_gateway": {"stub_overrides": off}}))

    assert auto_share.share_declared_servers() == []
    assert auto_share.share_declared_servers() == []
    assert _config(tmp_path)["mcp_gateway"]["stub_overrides"] == off


def test_sharing_turned_off_records_no_stub(tmp_path, toggle_home):
    _declare(toggle_home, "agent spec", _APPROVED_CMD, [])
    (tmp_path / "config.json").write_text(json.dumps({"mcp_gateway": {"enabled": False}}))

    assert auto_share.share_declared_servers() == []
    assert "stub_overrides" not in _config(tmp_path)["mcp_gateway"]


def test_a_global_off_saved_before_the_lock_wins(tmp_path, toggle_home, monkeypatch):
    """The decision is taken again on the locked document, not the first read."""
    import kiro_crew.config.loader as loader

    _declare(toggle_home, "agent spec", _APPROVED_CMD, [])
    locked = loader.update_config_locked

    def _off_lands_first(*args, **kwargs):
        (tmp_path / "config.json").write_text(json.dumps({"mcp_gateway": {"enabled": False}}))
        return locked(*args, **kwargs)

    monkeypatch.setattr(loader, "update_config_locked", _off_lands_first)

    assert auto_share.share_declared_servers() == []
    assert "stub_overrides" not in _config(tmp_path)["mcp_gateway"]


def test_a_launch_that_names_no_folder_needs_no_folder_answer(toggle_home):
    _declare(toggle_home, "agent spec", _APPROVED_CMD, ["-m", "srv"])
    facts = folder_use.read_declarations(toggle_home)

    assert facts.launch_free("srv")
    assert folder_use.folder_free_source("srv", frozenset(), None, launch_free=True) == (
        folder_use.SOURCE_LAUNCH
    )
    # A server that asked a chat for its roots, or was answered ``uses_cwd``, still asks.
    assert (
        folder_use.folder_free_source("srv", frozenset(), None, asked_roots=True, launch_free=True)
        is None
    )
    assert folder_use.folder_free_source("srv", frozenset(), "uses_cwd", launch_free=True) is None

    _declare(toggle_home, "agent spec", _APPROVED_CMD, ["./server.py"])
    assert not folder_use.read_declarations(toggle_home).launch_free("srv")


def test_a_shared_server_whose_launch_now_names_the_folder_stays_per_chat(tmp_path, toggle_home):
    """The folder rule holds on every start, not only when a server is first shared."""
    _declare(toggle_home, "agent spec", _APPROVED_CMD, ["/data"])
    assert auto_share.share_declared_servers() == ["srv"]
    target_env, _approvals = _boot(tmp_path, toggle_home, frozenset({"srv"}))
    assert _targets_running(target_env, _APPROVED_CMD)

    _declare(toggle_home, "agent spec", _APPROVED_CMD, ["."])
    target_env, approvals = _boot(tmp_path, toggle_home, frozenset({"srv"}))

    assert _targets_running(target_env, _APPROVED_CMD) == []
    assert approvals.refused == {}

    # An unchanged start is served from the rewrite cache and keeps it per chat.
    target_env, _approvals = _boot(tmp_path, toggle_home, frozenset({"srv"}))
    assert _targets_running(target_env, _APPROVED_CMD) == []


def test_the_rebuilds_secret_withhold_is_not_an_owner_off(toggle_home):
    from kiro_crew.mcp_provenance import WITHHELD_KEY

    entry = {"command": "npx", "env": {"TOKEN": "secret://vault/t"}, "disabled": True}
    _agents(toggle_home, a={"vaulted": {**entry, WITHHELD_KEY: True}, "off": entry})

    assert auto_share.share_declared_servers() == ["vaulted"]


def test_the_boot_pass_applies_new_stubs_live(tmp_path, toggle_home):
    """Run after the socket binds, it hands new stubs to the live apply path."""
    import asyncio
    from types import SimpleNamespace

    from kiro_crew.config.loader import KiroCrewConfig
    from kiro_crew.slack import gateway as gw

    _declare(toggle_home, "agent spec", _APPROVED_CMD, [])
    applied: list[bool] = []

    async def _apply():
        applied.append(True)
        return {"applied": True}

    orch = SimpleNamespace(_cfg=KiroCrewConfig.load(), _apply_mcp_stub=_apply)

    asyncio.run(gw.GatewayOrchestrator._auto_share_mcp_servers(orch))
    assert applied == [True]
    assert _config(tmp_path)["mcp_gateway"]["stub_overrides"] == {"srv": True}

    # A second start finds every server decided: nothing to apply.
    asyncio.run(gw.GatewayOrchestrator._auto_share_mcp_servers(orch))
    assert applied == [True]


def test_an_unchanged_start_with_a_saved_folder_answer_is_served_from_cache(tmp_path, toggle_home):
    """The folder inputs in the cache key survive the fingerprint's JSON round trip."""
    mod = _approval_module()
    _declare(toggle_home, "agent spec", _APPROVED_CMD, [])

    def _pass():
        approvals = mod.load_approvals()
        approvals.auto = True
        rewriter.rewrite_agents(
            source_dir=toggle_home,
            overlay_dir=tmp_path / "boot" / "mcp-gateway" / "agents",
            socket_path=tmp_path / "gw.sock",
            work_dir=tmp_path / "work",
            stub_servers=frozenset({"srv"}),
            approvals=approvals,
            cwd_answers={"srv": "not_used"},
            cwd_bindings={"srv": "binding"},
        )
        mod.save_pass(approvals)
        return approvals

    assert _pass().full_pass is True
    # The first pass recorded the launch, which is in the key; from then on an
    # unchanged start is a cache hit.
    _pass()
    assert _pass().full_pass is False

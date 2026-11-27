"""Share every stdio MCP server by default, at gateway start.

With sharing on (``mcp_gateway.enabled``, the default), each declared stdio
server that nobody has decided about is stubbed: the gateway start records
``stub_overrides[name] = true`` in config, so the MCP Servers page shows the
real state and the person can turn the server off there. A person's off is
stored as ``false`` (``mcp_gateway_stubs._record_stub_decisions`` always stores
an off), and any stored decision, on or off, is never touched here, so an off
survives every restart. Turning sharing off skips this pass entirely.

The candidates are read from the same declaration fleet the rewriter wraps
(``folder_use.read_declarations``: every agent spec, the admitted crewmates and
the global settings file), and every decision is matched by the server's
canonical alias as well as its exact name, so an off saved under one spelling
holds for the other. The whole decision is taken again inside the config lock,
from the document as it stands then and the ``config.local.json`` overlay, so
a global off or a folder answer saved meanwhile wins.

Left per chat, with no step for the person:

* a server disabled in any declaration (never spawned: probing and running it
  are what consent gates);
* a never-pooled server (``rewriter_spec.is_unpoolable``);
* Kiro Crew's own ``kirocrew-*`` servers, which follow their own roster;
* a server one of whose declarations names the chat's folder in an arg or env
  value (``.``, a relative path, a folder placeholder:
  ``change_card_mcp_server.detects_chat_folder``), since a shared backend runs
  in one fixed folder;
* a server answered ``uses_cwd``, which the stub resolver already drops;
* every server, when one declaration source could not be read.

A server that asks a chat for its roots is kept per chat by the rewriter
(``folder_use.roots_keeps_per_chat``), whatever this pass recorded.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Collection

logger = logging.getLogger(__name__)


def _aliases(names: Collection[str]) -> set[str]:
    from kiro_crew.mcp_utils import mcp_server_alias

    return {n for n in names if isinstance(n, str)} | {
        mcp_server_alias(n) for n in names if isinstance(n, str)
    }


def candidates(declarations: Any, gateway: Any) -> list[str]:
    """Names in *declarations* this pass would stub, given an ``McpGatewayConfig``. Pure.

    *declarations* is a ``folder_use.FolderDeclarations``; nothing is picked
    when it is incomplete.
    """
    from kiro_crew.mcp_gateway.rewriter_spec import is_unpoolable
    from kiro_crew.mcp_utils import mcp_server_alias

    if not gateway.enabled or not declarations.complete:
        return []
    decided = _aliases([*gateway.stub_overrides, *gateway.stub_servers, *gateway.cwd_use])
    kept = _aliases([*declarations.folder_named, *declarations.disabled])
    return sorted(
        name
        for name in declarations.stdio
        if not ({name, mcp_server_alias(name)} & (decided | kept)) and not is_unpoolable(name)
        # Kiro Crew's own servers follow their roster and leader
        # (``config.integration_sections.MANAGED_STUB_FOLLOWERS``); the opt-in
        # ones (``kirocrew-computer``, ``kirocrew-secrets``) stay a choice.
        and not mcp_server_alias(name).startswith("kirocrew-")
    )


def _overlay_section() -> dict:
    """``mcp_gateway`` from ``config.local.json``, read as the loader reads it, or ``{}``."""
    from kiro_crew.config.loader import config_local_path, read_endorsed_config_text

    try:
        raw = json.loads(read_endorsed_config_text(config_local_path()))
    except (OSError, ValueError):
        return {}
    section = raw.get("mcp_gateway") if isinstance(raw, dict) else None
    return section if isinstance(section, dict) else {}


def share_declared_servers() -> list[str]:
    """Record a stub for every undecided stdio server; return the names added. BLOCKING.

    Best effort: a failure leaves config as it was (those servers run per chat)
    and is logged.
    """
    from kiro_crew.config.loader import KiroCrewConfig, update_config_locked
    from kiro_crew.config.paths import kiro_agents_dir, mate_agents_dir
    from kiro_crew.config.resolution import _deep_merge
    from kiro_crew.config.section_builders import _build_mcp_gateway_config
    from kiro_crew.mcp_gateway.folder_use import read_declarations

    added: list[str] = []
    try:
        # A cheap first read, so a start with nothing to share takes no lock.
        if not KiroCrewConfig.load().mcp_gateway.enabled:
            return []
        declarations = read_declarations(kiro_agents_dir(), mate_agents_dir())
        overlay = _overlay_section()
        # Steady state (every server decided) takes no config lock and writes
        # nothing; the locked pass below decides again before it writes.
        if not candidates(declarations, KiroCrewConfig.load().mcp_gateway):
            return []

        def _mutate(data: dict) -> dict | None:
            section = data.setdefault("mcp_gateway", {})
            if not isinstance(section, dict):
                return None
            # Decided again on the locked document: a global off, a decision or a
            # folder answer saved since the first read wins.
            gateway = _build_mcp_gateway_config(_deep_merge(section, overlay))
            fresh = candidates(declarations, gateway)
            if not fresh:
                return None
            overrides = section.get("stub_overrides")
            overrides = dict(overrides) if isinstance(overrides, dict) else {}
            overrides.update({name: True for name in fresh})
            section["stub_overrides"] = {n: overrides[n] for n in sorted(overrides)}
            added.extend(fresh)
            return data

        update_config_locked(mutate=_mutate)
    except Exception:  # noqa: BLE001 -- the start goes on with the stubs it has
        logger.warning("mcp auto-share: could not record stubs for new servers", exc_info=True)
        return []
    if added:
        logger.info(
            "mcp auto-share: sharing %s (turn one off on the MCP Servers page)",
            ", ".join(added),
        )
    return added

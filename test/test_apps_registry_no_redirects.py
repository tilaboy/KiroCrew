"""Registry git fetches reach only the host the clone-host check approved.

A real ``git`` child talks to a loopback server that answers 302 to a second
loopback server. A gateway registry fetch must not follow it, so the second server
gets no request, and the install error tells the owner to list the repository's
current URL. The operator's own ``kirocrew app install <url>`` keeps git's default
and still follows the redirect.
"""

from __future__ import annotations

import http.server
import shutil
import subprocess
import threading

import pytest
from apps_registry_helpers import _catalog_absent  # noqa: F401 - fixture
from apps_registry_helpers import _explicit_registry_execution_admission  # noqa: F401 - fixture
from apps_registry_helpers import unsandboxed_spawn  # noqa: F401 - fixture

from kiro_crew.apps import git_install, registry
from kiro_crew.apps.registry_pipeline import checkout, manifests
from kiro_crew.apps.registry_pipeline.checkout import (
    _HOOKS_NEUTRALIZER_ARGV,
    _REDIRECT_CONFIG_REFUSAL,
    _redirect_config_refusal,
)
from kiro_crew.apps.registry_pipeline.git_targets import _lfs_endpoint_pin_argv
from kiro_crew.apps.registry_pipeline.subprocess_env import anonymous_git_env, minimal_env
from kiro_crew.testing.wait import FALLBACK_TIMEOUT_SECS

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


class _Recorder(http.server.BaseHTTPRequestHandler):
    status = 404
    location = ""
    paths: list[str]

    def do_GET(self):  # noqa: N802 - http.server API
        self.paths.append(self.path)
        self.send_response(self.status)
        if self.location:
            self.send_header("Location", self.location + self.path)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def redirecting(monkeypatch):
    """``(first_url, first_paths, second_url, second_paths)``; the first 302s to the second."""
    for key in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(key, raising=False)
    servers = []

    def serve(status, location=""):
        handler = type("_H", (_Recorder,), {"status": status, "location": location, "paths": []})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}", handler.paths

    second, second_paths = serve(404)
    first, first_paths = serve(302, second)
    yield f"{first}/owner/demo.git", first_paths, second, second_paths
    for server in servers:
        server.shutdown()


def _ls_remote(config_argv, url: str, cwd) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *config_argv, "ls-remote", url],
        capture_output=True,
        env=anonymous_git_env(),
        cwd=cwd,
        timeout=FALLBACK_TIMEOUT_SECS,
    )


def test_the_registry_git_argv_does_not_follow_a_redirect(redirecting, tmp_path):
    first_url, first_paths, _second, second_paths = redirecting

    result = _ls_remote(_HOOKS_NEUTRALIZER_ARGV, first_url, tmp_path)

    assert result.returncode != 0
    assert first_paths
    assert second_paths == []


def test_no_config_key_is_built_from_url_text():
    # No -c key is derived from URL text, so an index URL with "=" and ".proxy="
    # in its path cannot inject an http.<...>.proxy config key. The only -c keys
    # are the static neutralizer (generic redirect, hooks, fsmonitor) and the LFS
    # pin, whose value carries the URL after its single "=".
    url = "https://h.example/o/r=.proxy=http://169.254.169.254/"
    neutralizer = list(_HOOKS_NEUTRALIZER_ARGV)
    assert neutralizer.count("http.followRedirects=false") == 1
    pin = list(_lfs_endpoint_pin_argv(url))
    keys = [
        tok.split("=", 1)[0]
        for prev, tok in zip(["git", *neutralizer, *pin], [*neutralizer, *pin])
        if prev == "-c"
    ]
    assert all(
        k in {"core.hooksPath", "core.fsmonitor", "http.followRedirects", "lfs.url"} for k in keys
    ), keys
    assert not any(k.startswith("http.") and k != "http.followRedirects" for k in keys)
    assert not any("proxy" in k for k in keys)
    assert "s3cr3t-token" not in " ".join([*neutralizer, *pin])


def test_a_token_as_username_url_never_appears_in_argv_or_refusal():
    # No -c key derives from the URL, so a token used as the URL username reaches
    # no config key. The static neutralizer carries no URL at all, and the refusal
    # reason names no config key or value.
    token = "s3cr3t-token"
    assert token not in " ".join(_HOOKS_NEUTRALIZER_ARGV)
    assert not any(
        a.startswith("http.") and a != "http.followRedirects=false" for a in _HOOKS_NEUTRALIZER_ARGV
    )
    assert "http." not in _REDIRECT_CONFIG_REFUSAL
    assert "followredirects" not in _REDIRECT_CONFIG_REFUSAL.lower()


def _git(checkout_dir, *args, env):
    subprocess.run(["git", "-C", str(checkout_dir), *args], env=env, timeout=FALLBACK_TIMEOUT_SECS)


def test_a_local_username_qualified_redirect_key_is_refused(tmp_path):
    import asyncio

    env = anonymous_git_env()
    checkout_dir = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout_dir)], env=env, timeout=FALLBACK_TIMEOUT_SECS)
    _git(checkout_dir, "config", "http.https://tok@h.example/o/r.followRedirects", "true", env=env)
    reason = asyncio.run(_redirect_config_refusal(env, checkout_dir))
    assert reason == _REDIRECT_CONFIG_REFUSAL


def test_a_global_username_qualified_redirect_key_is_refused_for_owner_fetch(tmp_path):
    import asyncio

    # An owner-designated fetch runs under minimal_env, which keeps global config
    # in scope. A username-qualified followRedirects=true in GLOBAL config is read
    # exactly as the fetch would read it, so the guard refuses.
    global_cfg = tmp_path / "gitconfig"
    global_cfg.write_text(
        '[http "https://tok@h.example/o/r"]\n\tfollowRedirects = true\n', encoding="utf-8"
    )
    env = minimal_env()
    env["GIT_CONFIG_GLOBAL"] = str(global_cfg)
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    reason = asyncio.run(_redirect_config_refusal(env, neutral))
    assert reason == _REDIRECT_CONFIG_REFUSAL


def test_bool_synonyms_and_includes(tmp_path):
    import asyncio

    env = anonymous_git_env()
    checkout_dir = tmp_path / "c"
    subprocess.run(["git", "init", "-q", str(checkout_dir)], env=env, timeout=FALLBACK_TIMEOUT_SECS)

    def scan():
        return asyncio.run(_redirect_config_refusal(env, checkout_dir))

    # No URL-scoped entry: allowed. The generic key alone is never matched.
    assert scan() is None
    _git(checkout_dir, "config", "http.followRedirects", "true", env=env)
    assert scan() is None  # the bare generic key is not URL-scoped
    # A URL-scoped false / synonym is allowed.
    _git(checkout_dir, "config", "http.https://h/r.followRedirects", "no", env=env)
    assert scan() is None
    # A URL-scoped truthy entry is refused.
    _git(checkout_dir, "config", "http.https://h/r.followRedirects", "true", env=env)
    assert scan() == _REDIRECT_CONFIG_REFUSAL


def test_a_url_key_with_a_space_is_parsed_whole(tmp_path):
    import asyncio

    # A URL subsection containing a space would split a space-delimited read so the
    # value reads as part of the key and the refusal is skipped. The -z read keys on
    # the record's first newline instead, so the whole key is kept.
    env = anonymous_git_env()
    checkout_dir = tmp_path / "c"
    subprocess.run(["git", "init", "-q", str(checkout_dir)], env=env, timeout=FALLBACK_TIMEOUT_SECS)
    key = "http.https://forge.example/foo bar.followRedirects"

    def scan():
        return asyncio.run(_redirect_config_refusal(env, checkout_dir))

    subprocess.run(
        ["git", "-C", str(checkout_dir), "config", key, "true"],
        env=env,
        timeout=FALLBACK_TIMEOUT_SECS,
    )
    assert scan() == _REDIRECT_CONFIG_REFUSAL
    subprocess.run(
        ["git", "-C", str(checkout_dir), "config", key, "false"],
        env=env,
        timeout=FALLBACK_TIMEOUT_SECS,
    )
    assert scan() is None


def test_a_redirect_key_in_an_included_file_is_refused(tmp_path):
    import asyncio

    env = anonymous_git_env()
    checkout_dir = tmp_path / "c"
    subprocess.run(["git", "init", "-q", str(checkout_dir)], env=env, timeout=FALLBACK_TIMEOUT_SECS)
    included = tmp_path / "extra.cfg"
    included.write_text('[http "https://h/r"]\n\tfollowRedirects = true\n', encoding="utf-8")
    # --local would turn includes off; the guard reads with includes on, as the
    # fetch does, so a URL-scoped key behind include.path is still caught.
    _git(checkout_dir, "config", "include.path", str(included), env=env)
    assert asyncio.run(_redirect_config_refusal(env, checkout_dir)) == _REDIRECT_CONFIG_REFUSAL


def _global_redirect_env(tmp_path, host):
    # minimal_env keeps global config in scope (owner-designated posture); point
    # GIT_CONFIG_GLOBAL at a file whose URL-scoped key enables redirects.
    global_cfg = tmp_path / "gitconfig"
    global_cfg.write_text(f'[http "http://{host}/"]\n\tfollowRedirects = true\n', encoding="utf-8")
    env = minimal_env()
    env["GIT_CONFIG_GLOBAL"] = str(global_cfg)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


@pytest.mark.asyncio
async def test_a_pinned_fetch_is_refused_by_a_global_redirect_key(redirecting, tmp_path):
    # An owner-designated pinned fetch reads GLOBAL config. A URL-scoped
    # followRedirects=true there is caught by the in-run guard before the network
    # op, so the fetch is refused and no request reaches the redirect target.
    first_url, first_paths, _second, second_paths = redirecting
    host = first_url.split("//", 1)[1].split("/", 1)[0]
    clone_env = _global_redirect_env(tmp_path, host)
    result = await checkout._git_fetch_commit(
        first_url,
        "a" * 40,
        tmp_path / "dest",
        [],
        clone_env=clone_env,
        sandbox_mode="strict",
    )
    assert result is not None and result["ok"] is False
    assert result["code"] == "checkout_enables_redirects"
    assert first_paths == [] and second_paths == []


@pytest.mark.asyncio
async def test_an_isolated_transport_branch_fetch_is_refused_by_a_global_redirect_key(
    redirecting, tmp_path
):
    # The isolate-transport branch fetch (embedded userinfo) also goes through the
    # in-run guard, so a GLOBAL URL-scoped redirect key refuses it before network.
    first_url, first_paths, _second, second_paths = redirecting
    scheme, _, rest = first_url.partition("://")
    host = rest.split("/", 1)[0]
    cred_url = f"{scheme}://user:tok@{rest}"  # embedded userinfo -> isolate transport
    clone_env = _global_redirect_env(tmp_path, host)
    result = await checkout._git_fetch_branch(
        first_url,  # git_url is credential-free; the userinfo rides credential_target
        "main",
        tmp_path / "dest",
        [],
        credential_target=cred_url,
        clone_env=clone_env,
        sandbox_mode="strict",
    )
    assert result is not None and result["ok"] is False
    assert result["code"] == "checkout_enables_redirects"
    assert first_paths == [] and second_paths == []


def test_the_cli_install_argv_still_follows_a_redirect(redirecting, tmp_path):
    first_url, first_paths, _second, second_paths = redirecting
    # The CLI allows only https and ssh; open http for this loopback server alone,
    # keeping every other pair the CLI passes.
    config_argv = [*git_install._git_config_argv(), "-c", "protocol.http.allow=always"]

    _ls_remote(config_argv, first_url, tmp_path)

    assert first_paths
    assert second_paths  # git followed the redirect, as a plain ``git clone`` does


@pytest.mark.asyncio
async def test_the_listing_manifest_fetch_does_not_follow_a_redirect(redirecting, monkeypatch):
    first_url, first_paths, _second, second_paths = redirecting
    # The first host passes the clone-host check; the one it redirects to would not.
    monkeypatch.setattr(manifests, "is_clone_host_trusted", lambda url: True)

    async def _passthrough(argv, **_kw):
        return argv, None

    monkeypatch.setattr(manifests, "wrap_argv_async", _passthrough)
    monkeypatch.setattr(manifests, "cgroup_scope_argv", lambda argv: argv)

    result = await manifests._fetch_app_manifest("owner/demo", "main", git_url=first_url)

    assert result is None
    assert first_paths
    assert second_paths == []


@pytest.mark.asyncio
async def test_the_install_clone_says_to_list_the_current_url(redirecting, monkeypatch, tmp_path):
    first_url, first_paths, _second, second_paths = redirecting
    monkeypatch.setattr(checkout, "is_clone_host_trusted", lambda url: True, raising=False)
    log: list[str] = []

    result = await registry._git_clone_or_pull(
        first_url, "main", tmp_path / "demo", log, index_originated=True
    )

    assert result is not None and result["ok"] is False
    assert "the server redirects" in result["error"]
    assert "list the repository's current URL in the registry" in result["error"]
    assert second_paths == []


@pytest.mark.asyncio
async def test_the_external_index_clone_is_refused_by_a_global_redirect_key(
    redirecting, monkeypatch, tmp_path
):
    # The external-registry index clone (indexes._fetch_external_registry_index,
    # owner-designated plain-clone branch) builds its env from ``minimal_env``,
    # which keeps GLOBAL git config in scope. A URL-scoped followRedirects=true
    # there is read by the in-line guard with the same env+cwd as the clone, so
    # the clone is refused before the network op and neither server is reached.
    # Reds on origin/main: with no guard the clone runs and the global redirect
    # key sends git to the second host.
    from kiro_crew.apps import registry as registry_mod
    from kiro_crew.apps.registry_pipeline import indexes

    first_url, first_paths, _second, second_paths = redirecting
    host = first_url.split("//", 1)[1].split("/", 1)[0]
    env = _global_redirect_env(tmp_path, host)
    monkeypatch.setattr(indexes, "minimal_env", lambda **extra: {**env, **extra})
    monkeypatch.setattr(indexes, "_context_clone_sandbox_mode", lambda url: "strict")
    monkeypatch.setattr(registry_mod, "is_clone_host_trusted", lambda url: True)

    async def _passthrough(argv, **_kw):
        return argv, None

    monkeypatch.setattr(indexes, "wrap_argv_async", _passthrough)
    monkeypatch.setattr(indexes, "cgroup_scope_argv", lambda argv: argv)

    result = await indexes._fetch_external_registry_index(first_url, "main")

    # ``None`` is the fetch's failure marker (not ``[]``), so a refused refresh
    # never overwrites the cached index with an empty one.
    assert result is None
    assert first_paths == [] and second_paths == []


@pytest.mark.asyncio
async def test_the_blob_proxy_clone_is_refused_by_a_global_redirect_key(
    redirecting, monkeypatch, tmp_path
):
    # The browse-time blob clone (routes_art._fetch_git_blob, owner-designated
    # plain-clone branch) also builds its env from ``minimal_env`` with GLOBAL
    # config in scope. The in-line guard refuses before the network op, so no
    # request reaches either loopback server. Reds on origin/main: without the
    # guard the clone follows the global redirect key to the second host.
    from kiro_crew.apps import registry as registry_mod
    from kiro_crew.apps import routes_art

    first_url, first_paths, _second, second_paths = redirecting
    host = first_url.split("//", 1)[1].split("/", 1)[0]
    env = _global_redirect_env(tmp_path, host)
    monkeypatch.setattr(routes_art, "minimal_env", lambda **extra: {**env, **extra})
    monkeypatch.setattr(routes_art, "_context_clone_sandbox_mode", lambda url: "strict")
    monkeypatch.setattr(routes_art, "_sel_credential_grant", lambda *a, **k: None)
    monkeypatch.setattr(registry_mod, "is_clone_host_trusted", lambda url: True)

    async def _passthrough(argv, **_kw):
        return argv, None

    monkeypatch.setattr(routes_art, "wrap_argv_async", _passthrough)
    monkeypatch.setattr(routes_art, "cgroup_scope_argv", lambda argv: argv)

    ok = await routes_art._fetch_git_blob(
        "owner/demo",
        "main",
        "icon.png",
        tmp_path / "blob-cache",
        git_url=first_url,
        owner_designated=True,
    )

    assert ok is False
    assert first_paths == [] and second_paths == []

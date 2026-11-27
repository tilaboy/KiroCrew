"""Update a Windows desktop install whose gateway runs without the desktop app.

The desktop app (NSIS) bundles this backend. When the app hosts the gateway it
sets ``KIROCREW_DESKTOP_GATEWAY`` and its own updater owns the update. A gateway
started from the bundled ``kirocrew.cmd`` with no window (over SSH or SSM) has no
updater at all, so this module gives it one (decision entry "a headless Windows
desktop install updates from its gateway"):

* **check**: read the same release feed the app's updater reads
  (``feed/<channel>/latest.yml``) and parse the release it offers;
* **stage**: download the signed installer into the data home and verify it:
  the feed's sha512 and size, a valid Authenticode signature with an RFC 3161
  timestamp, a signer the app's own updater pins (``publisherName`` in
  ``resources/app-update.yml``), and a version newer than the running one;
* **hand off**: the installer replaces the files the gateway runs from, which
  Windows keeps locked while the gateway runs, so it is run by a detached
  PowerShell helper that waits for the gateway (and the CLI) to exit, verifies
  the staged file again while holding it open against writers, runs it silently
  in the scope the install was made in, checks the installed version, writes a
  result record, and starts the gateway again with the arguments it had.

Nothing here runs while a gateway serves: the hand-off happens at the start a
person caused (decision entry "updates never restart a running gateway"). Every
check fails closed: an error leaves the old install in place, and the helper's
own failure is reported at the next start as ``pending_apply_error``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

#: The distribution stamp of the Windows desktop installer.
NSIS_DISTRIBUTION = "nsis"

#: Installer file names a desktop feed may name. The LTS edition publishes its own.
_INSTALLER_NAMES = frozenset({"KiroCrew-Setup.exe", "KiroCrew-LTS-Setup.exe"})  # brand-ok

#: Channels with a Windows desktop publish lane (``website/electron/auto-update.js``).
DESKTOP_CHANNELS = ("nightly", "insider", "stable", "lts")

#: A feed carries release notes, so it is larger than the CLI manifest.
FEED_MAX_BYTES = 1024 * 1024
FEED_TIMEOUT_SECS = 15.0

#: The largest installer accepted, whatever the feed says.
INSTALLER_MAX_BYTES = 2 * 1024 * 1024 * 1024

#: Bound of one installer download.
DOWNLOAD_TIMEOUT_SECS = 900.0

#: Bound of the signature probe.
_SIGNATURE_TIMEOUT_SECS = 60.0

#: Bound the helper waits for the gateway to exit, and for the installer to finish.
HELPER_WAIT_EXIT_SECS = 300
HELPER_INSTALL_SECS = 900

#: Data-home names: the staged installer, the helper's result and its log.
STAGING_DIR = "desktop-update"
RESULT_FILE = "desktop_update_result.json"
HELPER_LOG = "desktop-update.log"
GATEWAY_OUTPUT = "desktop-update-gateway"

#: Error codes; the text that goes with each is the exception's message.
ERR_NOT_WINDOWS = "not_windows"
ERR_NO_INSTALL = "install_not_found"
ERR_SOURCE = "source_not_allowed"
ERR_FEED = "feed_unusable"
ERR_FEED_UNREACHABLE = "feed_unreachable"
ERR_DOWNGRADE = "not_newer"
ERR_VERSION_CHANGED = "version_changed"
ERR_DOWNLOAD = "download_failed"
ERR_DIGEST = "digest_mismatch"
ERR_SIGNATURE = "signature_invalid"
ERR_SIGNER = "signer_mismatch"
ERR_SCOPE = "scope_unknown"
ERR_ELEVATION = "needs_administrator"
ERR_HELPER = "helper_failed"

_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.]{1,48})?")
_SHA512_B64_RE = re.compile(r"[A-Za-z0-9+/]{86}==")


class DesktopUpdateError(Exception):
    """A refusal with a machine-readable *code*; the message is for a person."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class FeedRelease:
    """The release a desktop feed offers, after validation."""

    version: str
    url: str
    sha512: str
    size: int
    channel: str


# --- shape -------------------------------------------------------------------


def _on_windows() -> bool:
    return sys.platform == "win32"


def hosted_by_desktop() -> bool:
    """Whether the desktop app spawned this process's gateway (and so owns updates)."""
    from kiro_crew.update_boot_apply import DESKTOP_HOSTED_ENV

    return bool(os.environ.get(DESKTOP_HOSTED_ENV))


def headless_desktop_install(dist: str | None = None) -> bool:
    """Is this the Windows desktop bundle, running without the desktop app?

    The baked stamp, the platform and the absence of the variable the app sets on
    the gateway it hosts. No I/O.
    """
    if dist is None:
        from kiro_crew.beacon import distribution

        dist = distribution()
    return dist == NSIS_DISTRIBUTION and _on_windows() and not hosted_by_desktop()


def install_dir(start: Path | None = None) -> Path | None:
    """The desktop install directory this backend was unpacked into, or ``None``.

    The nearest ancestor of the ``kiro_crew`` package that holds both
    ``resources/app-update.yml`` and ``resources/backend-dist``: the layout
    electron-builder writes and ``packaging/`` bundles the backend into.
    """
    if start is None:
        import kiro_crew

        start = Path(kiro_crew.__file__).resolve().parent
    for parent in (start, *start.parents):
        res = parent / "resources"
        if (res / "app-update.yml").is_file() and (res / "backend-dist").is_dir():
            return parent
    return None


def pinned_publishers(root: Path) -> tuple[str, ...]:
    """The signer names the app's own updater accepts (``publisherName``).

    electron-builder writes them into ``resources/app-update.yml`` from
    ``win.signtoolOptions.publisherName``; ``NsisUpdater`` refuses an installer
    signed by anyone else, so this check is the same one. None found is a
    refusal, never "any signer".
    """
    import yaml  # type: ignore[import-untyped]

    try:
        data = yaml.safe_load((root / "resources" / "app-update.yml").read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise DesktopUpdateError(ERR_SIGNER, f"The app's update settings are unreadable: {exc}")
    names = data.get("publisherName") if isinstance(data, dict) else None
    if isinstance(names, str):
        names = [names]
    pinned = tuple(n.strip() for n in names or () if isinstance(n, str) and n.strip())
    if not pinned:
        raise DesktopUpdateError(ERR_SIGNER, "The app's update settings pin no installer signer.")
    return pinned


# --- channel and source --------------------------------------------------------


def desktop_channel(running_version: str) -> str | None:
    """The feed channel this install follows, mirroring the app's ``resolveChannel``.

    A nightly build stays on nightly. Otherwise the channel the gateway follows
    (the policy pin, the LTS lane, or the data home's ``channel`` file, default
    stable). A production build asked for nightly has no lane: that is a
    separate side-by-side app.
    """
    from kiro_crew import release_channel as stamp
    from kiro_crew.platform.update_layout import policy_release_channel, release_channel

    if stamp.channel(running_version) == "nightly":
        # A required channel wins, and a nightly build cannot follow any other
        # lane (it is a separate side-by-side app), so that pair has none.
        required = policy_release_channel()
        return "nightly" if required in ("", "nightly") else None
    channel = release_channel()
    return channel if channel in ("insider", "stable", "lts") else None


def source_refusal() -> str | None:
    """Why the update source may not be used, or ``None`` when it may.

    The bases must be HTTPS with no shell metacharacters, and the security
    policy's source pin must allow the feed base.
    """
    from kiro_crew.platform.update_governance import update_blocked_reason
    from kiro_crew.platform.update_layout import cdn_bases, cdn_bases_are_safe

    if not cdn_bases_are_safe():
        return "The update source is not a safe HTTPS address."
    for base in cdn_bases():
        reason = update_blocked_reason(base)
        if reason:
            return reason
    return None


def provider_owns_updates() -> bool:
    """Whether a security-policy update provider owns this host's updates.

    Every surface consults the provider first; this path must not install the
    desktop installer where a provider (or its refusal) decides.
    """
    from kiro_crew.platform.update_provider import resolve_provider

    return resolve_provider() is not None


def source_overridden() -> bool:
    """Whether ``KIROCREW_CDN_BASE`` replaces the official source (host approval only)."""
    return bool((os.environ.get("KIROCREW_CDN_BASE") or "").strip())


def feed_url(channel: str) -> str:
    from kiro_crew.platform.update_layout import cdn_bases

    return f"{cdn_bases()[0]}/feed/{channel}/latest.yml"


def parse_feed(raw: bytes, *, channel: str) -> FeedRelease:
    """Validate an electron-builder ``latest.yml``; raise :class:`DesktopUpdateError`.

    The installer URL must be exactly the artifact base's
    ``desktop/<channel>/<version>/<installer>``: a feed that names any other host,
    channel or version is refused, so a tampered feed cannot point the download
    anywhere else. The sha512 must be well formed and agree between the
    top-level entry and ``files``.
    """
    import yaml  # type: ignore[import-untyped]

    from kiro_crew.platform.update_layout import cdn_bases

    if len(raw) > FEED_MAX_BYTES:
        raise DesktopUpdateError(ERR_FEED, "The release feed is too large.")
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise DesktopUpdateError(ERR_FEED, f"The release feed is not valid YAML: {exc}")
    if not isinstance(data, dict):
        raise DesktopUpdateError(ERR_FEED, "The release feed is not a mapping.")
    version = data.get("version")
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise DesktopUpdateError(ERR_FEED, "The release feed names no usable version.")
    files = data.get("files")
    if not isinstance(files, list) or not files or not isinstance(files[0], dict):
        raise DesktopUpdateError(ERR_FEED, "The release feed lists no installer.")
    entry = files[0]
    url, sha512, size = entry.get("url"), entry.get("sha512"), entry.get("size")
    if data.get("path") not in (None, url) or data.get("sha512") not in (None, sha512):
        raise DesktopUpdateError(ERR_FEED, "The release feed names two different installers.")
    if not isinstance(sha512, str) or not _SHA512_B64_RE.fullmatch(sha512):
        raise DesktopUpdateError(ERR_FEED, "The release feed carries no usable sha512.")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= INSTALLER_MAX_BYTES:
        raise DesktopUpdateError(ERR_FEED, "The release feed carries no usable size.")
    artifact_base = cdn_bases()[1]
    name = url.rsplit("/", 1)[-1] if isinstance(url, str) else ""
    # A stable release advances the insider feed too, and the publish lane copies
    # stable's feed there unchanged, so an insider feed may name stable's
    # installer. No other channel's artifact is accepted.
    lanes = ("insider", "stable") if channel == "insider" else (channel,)
    expected = {f"{artifact_base}/desktop/{lane}/{version}/{name}" for lane in lanes}
    if name not in _INSTALLER_NAMES or url not in expected:
        raise DesktopUpdateError(
            ERR_FEED, "The release feed points the installer somewhere other than this channel."
        )
    return FeedRelease(version=version, url=url, sha512=sha512, size=size, channel=channel)


def is_newer(candidate: str, running: str) -> bool | None:
    """Is *candidate* (SemVer, from the feed) newer than *running* (the backend's)?"""
    from kiro_crew.dashboard.handlers.updates_verdict import _is_newer

    return _is_newer(candidate, running)


def require_newer(release: FeedRelease, running: str) -> None:
    """Refuse an equal, older or unordered release: this path never downgrades."""
    if is_newer(release.version, running) is not True:
        raise DesktopUpdateError(
            ERR_DOWNGRADE,
            f"The release feed offers {release.version}, which is not newer than {running}.",
        )


async def fetch_feed(channel: str) -> FeedRelease:
    """Read and validate *channel*'s desktop feed."""
    from kiro_crew.dashboard.handlers._update_feed import fetch_feed_bytes

    url = feed_url(channel)
    try:
        status, raw = await fetch_feed_bytes(
            url, timeout_secs=FEED_TIMEOUT_SECS, max_bytes=FEED_MAX_BYTES
        )
    except Exception as exc:  # OSError, a timeout, aiohttp.ClientError and kin
        raise DesktopUpdateError(ERR_FEED_UNREACHABLE, f"The release feed could not be read: {exc}")
    if status != 200:
        raise DesktopUpdateError(ERR_FEED_UNREACHABLE, f"The release feed answered HTTP {status}.")
    return parse_feed(raw, channel=channel)


# --- staging and verification -------------------------------------------------


def staging_dir() -> Path:
    from kiro_crew.config.paths import data_home

    return data_home() / STAGING_DIR


def staged_path(release: FeedRelease) -> Path:
    name = release.url.rsplit("/", 1)[-1]
    return staging_dir() / f"{release.version}-{name}"


def sha512_b64(path: Path) -> str:
    digest = hashlib.sha512()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return base64.b64encode(digest.digest()).decode("ascii")


def verify_digest(path: Path, release: FeedRelease) -> None:
    try:
        size = path.stat().st_size
        actual = sha512_b64(path)
    except OSError as exc:
        raise DesktopUpdateError(ERR_DIGEST, f"The installer could not be read: {exc}")
    if size != release.size or actual != release.sha512:
        raise DesktopUpdateError(
            ERR_DIGEST, "The installer does not match the sha512 the release feed names."
        )


#: Reads the signature of the file in $env:KC_SIG_PATH. The path travels in the
#: environment, never in the script text, so no path can break the quoting.
_SIGNATURE_SCRIPT = (
    "$ErrorActionPreference='Stop';"
    "$s=Get-AuthenticodeSignature -LiteralPath $env:KC_SIG_PATH;"
    "$n='';if($s.SignerCertificate){$n=$s.SignerCertificate.GetNameInfo('SimpleName',$false)};"
    "[pscustomobject]@{status=[string]$s.Status;signer=$n;"
    "timestamped=[bool]$s.TimeStamperCertificate}|ConvertTo-Json -Compress"
)


def _powershell() -> str:
    from kiro_crew.platform_compat import trusted_system_bin

    found = trusted_system_bin("powershell")
    if not found:
        raise DesktopUpdateError(ERR_SIGNATURE, "Windows PowerShell was not found in System32.")
    return found


def read_signature(path: Path) -> dict[str, Any]:
    """``{"status", "signer", "timestamped"}`` from ``Get-AuthenticodeSignature``."""
    env = dict(os.environ, KC_SIG_PATH=str(path))
    try:
        proc = subprocess.run(
            [_powershell(), "-NoProfile", "-NonInteractive", "-Command", _SIGNATURE_SCRIPT],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_SIGNATURE_TIMEOUT_SECS,
            env=env,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DesktopUpdateError(ERR_SIGNATURE, f"The signature could not be read: {exc}")
    try:
        result = json.loads(proc.stdout.strip() or "null")
    except ValueError:
        result = None
    if proc.returncode != 0 or not isinstance(result, dict):
        raise DesktopUpdateError(ERR_SIGNATURE, "The signature could not be read.")
    return result


def verify_signature(
    path: Path,
    publishers: tuple[str, ...],
    *,
    reader: Callable[[Path], dict[str, Any]] = read_signature,
) -> None:
    """Refuse unless the signature is Valid, timestamped, and by a pinned signer."""
    info = reader(path)
    if info.get("status") != "Valid":
        raise DesktopUpdateError(
            ERR_SIGNATURE, f"The installer's signature is not valid ({info.get('status')})."
        )
    if info.get("timestamped") is not True:
        raise DesktopUpdateError(ERR_SIGNATURE, "The installer's signature has no timestamp.")
    if info.get("signer") not in publishers:
        raise DesktopUpdateError(
            ERR_SIGNER, "The installer is not signed by the publisher the app pins."
        )


async def _download(release: FeedRelease, dest: Path) -> None:
    """Stream the installer to *dest*, bounded by the feed's size."""
    import aiohttp

    from kiro_crew.http_proxy import resolve_proxy

    timeout = aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT_SECS)
    written = 0
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(release.url, proxy=resolve_proxy(release.url)) as resp:
                if resp.status != 200:
                    raise DesktopUpdateError(
                        ERR_DOWNLOAD, f"The installer download answered HTTP {resp.status}."
                    )
                # Opened and written off the loop: the data home can sit on a
                # slow disk, and a 400 MB write would stall every session.
                out = await asyncio.to_thread(open, dest, "wb")
                try:
                    async for chunk in resp.content.iter_chunked(1024 * 1024):
                        written += len(chunk)
                        if written > release.size:
                            raise DesktopUpdateError(
                                ERR_DIGEST, "The installer is larger than the feed says."
                            )
                        await asyncio.to_thread(out.write, chunk)
                finally:
                    await asyncio.to_thread(out.close)
    except DesktopUpdateError:
        raise
    except (OSError, asyncio.TimeoutError, aiohttp.ClientError) as exc:
        raise DesktopUpdateError(ERR_DOWNLOAD, f"The installer download failed: {exc}")


Downloader = Callable[[FeedRelease, Path], Awaitable[None]]


async def stage(
    release: FeedRelease,
    publishers: tuple[str, ...],
    *,
    download: Downloader = _download,
    signature_reader: Callable[[Path], dict[str, Any]] = read_signature,
) -> Path:
    """Download (unless already staged) and verify the installer; return its path.

    A staged file that fails verification is deleted, so the next try downloads
    it again rather than trusting it.
    """
    target = staged_path(release)
    await asyncio.to_thread(lambda: target.parent.mkdir(parents=True, exist_ok=True))
    have = await asyncio.to_thread(target.is_file)
    if not have:
        part = target.with_name(target.name + ".part")
        try:
            await download(release, part)
            await asyncio.to_thread(os.replace, part, target)
        finally:
            await asyncio.to_thread(_unlink_quietly, part)
        await asyncio.to_thread(_prune_staging, target)
    try:
        await asyncio.to_thread(verify_digest, target, release)
        await asyncio.to_thread(
            lambda: verify_signature(target, publishers, reader=signature_reader)
        )
    except DesktopUpdateError:
        await asyncio.to_thread(_unlink_quietly, target)
        raise
    return target


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _prune_staging(keep: Path) -> None:
    """Drop installers staged for other versions; they are 400 MB each."""
    try:
        entries = list(keep.parent.iterdir())
    except OSError:
        return
    for entry in entries:
        if entry != keep and entry.is_file() and entry.suffix in (".exe", ".part"):
            _unlink_quietly(entry)


# --- scope ---------------------------------------------------------------------

SCOPE_ALL_USERS = "allusers"
SCOPE_CURRENT_USER = "currentuser"

_UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"


def _uninstall_entries() -> list[tuple[str, str, str]]:
    """``(hive, display_version, uninstall_string)`` for every Kiro Crew entry."""
    # Typed ``Any``: mypy runs with ``--platform linux``, where ``winreg``'s
    # attributes are absent (the shape ``browser_harness.discover`` uses).
    import winreg as _winreg

    winreg: Any = _winreg
    found: list[tuple[str, str, str]] = []
    for hive_name, hive in (
        ("HKLM", winreg.HKEY_LOCAL_MACHINE),
        ("HKCU", winreg.HKEY_CURRENT_USER),
    ):
        try:
            root = winreg.OpenKey(hive, _UNINSTALL_KEY)
        except OSError:
            continue
        with root:
            index = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(root, sub) as key:
                        name = str(winreg.QueryValueEx(key, "DisplayName")[0])
                        uninstall = str(winreg.QueryValueEx(key, "UninstallString")[0])
                        version = str(winreg.QueryValueEx(key, "DisplayVersion")[0])
                except OSError:
                    continue
                if name.startswith("KiroCrew"):  # brand-ok
                    found.append((hive_name, version, uninstall))
    return found


def _entry_for(root: Path, entries: list[tuple[str, str, str]]) -> tuple[str, str, str] | None:
    """The uninstall entry whose uninstaller lives in *root*."""
    for hive, version, uninstall in entries:
        exe = uninstall.strip()
        exe = exe[1:].split('"', 1)[0] if exe.startswith('"') else exe.split(" /", 1)[0]
        try:
            if Path(exe).parent.resolve() == root.resolve():
                return hive, version, uninstall
        except OSError:
            continue
    return None


def install_scope(
    root: Path,
    *,
    entries: Callable[[], list[tuple[str, str, str]]] = _uninstall_entries,
) -> str:
    """Whether *root* was installed for all users or for the current user only.

    Read from the uninstall entry electron-builder registered: a per-machine
    install lives under ``HKLM``, a per-user one under ``HKCU``. No entry is a
    refusal, so the installer is never run in a guessed scope.
    """
    entry = _entry_for(root, entries())
    if entry is None:
        raise DesktopUpdateError(ERR_SCOPE, "No uninstall entry names this install directory.")
    return SCOPE_ALL_USERS if entry[0] == "HKLM" else SCOPE_CURRENT_USER


def installed_version(root: Path) -> str | None:
    """The version the uninstall entry for *root* reports, or ``None``."""
    try:
        entry = _entry_for(root, _uninstall_entries())
    except Exception:
        return None
    return entry[1] if entry else None


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def require_rights(scope: str, *, is_admin: Callable[[], bool] = _is_admin) -> None:
    if scope == SCOPE_ALL_USERS and not is_admin():
        raise DesktopUpdateError(
            ERR_ELEVATION,
            "This install is for all users, and the gateway's account is not an "
            "administrator, so it cannot update it.",
        )


# --- the helper ----------------------------------------------------------------


@dataclass(frozen=True)
class HelperPlan:
    """Everything the helper needs; rendered into its script as literals."""

    wait_pids: tuple[int, ...]
    installer: str
    sha512: str
    size: int
    publishers: tuple[str, ...]
    version: str
    scope: str
    install_dir: str
    result_path: str
    log_path: str
    #: ``()`` when nothing is started again afterwards (``kirocrew stop``/``update``).
    restart_argv: tuple[str, ...] = ()
    restart_cwd: str = ""
    #: Path stem of the started gateway's console output (``.out`` / ``.err``).
    gateway_output: str = ""


#: What an argument of the command that starts the gateway again may NOT hold.
#: The helper wraps each argument in double quotes and ``Start-Process`` hands the
#: joined line to CreateProcess (no shell), so only a quote, a control character
#: or a backslash before the closing quote can move an argument boundary. Any
#: other character, a user name's accents and apostrophes included, is kept.
_UNSAFE_ARG_RE = re.compile(r'["\x00-\x1f]')


def _ps_literal(value: str) -> str:
    """A PowerShell single-quoted literal: the only escape is a doubled quote."""
    if "\x00" in value:
        raise ValueError("NUL in a helper value")
    return "'" + value.replace("'", "''") + "'"


def _ps_array(values: tuple[str, ...]) -> str:
    return "@(" + ",".join(_ps_literal(v) for v in values) + ")"


_HELPER_BODY = r"""
$ErrorActionPreference = 'Stop'
function Log($m) { try { Add-Content -LiteralPath $LogPath -Value ("{0} {1}" -f (Get-Date -Format o), $m) } catch {} }
function Finish($ok, $err) {
  $r = [pscustomobject]@{ version = $Version; ok = $ok; error = $err; finished = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
  try { $r | ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultPath -Encoding UTF8 } catch { Log "result not written: $_" }
}
function Restart-Gateway {
  if ($RestartArgv.Count -eq 0) { return }
  try {
    # Windows PowerShell joins -ArgumentList with spaces, so each argument is
    # quoted; none holds a quote (checked before it got here). The console
    # output goes to files of its own: gateway.log is the gateway's own log,
    # and a redirect handle on it keeps the gateway from opening it at all.
    $rest = @()
    if ($RestartArgv.Count -gt 1) { $rest = $RestartArgv[1..($RestartArgv.Count - 1)] | ForEach-Object { '"' + $_ + '"' } }
    $p = Start-Process -FilePath $RestartArgv[0] -ArgumentList $rest -WorkingDirectory $RestartCwd -WindowStyle Hidden -RedirectStandardOutput ($GatewayOutput + '.out') -RedirectStandardError ($GatewayOutput + '.err') -PassThru
    Log "gateway started again: pid $($p.Id)"
  } catch { Log "gateway did not start again: $_" }
}
$proc = $null
$RunDir = $null
try {
  Log "waiting for pids $($WaitPids -join ',') to exit"
  $deadline = (Get-Date).AddSeconds($WaitSecs)
  foreach ($id in $WaitPids) {
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($p -and -not $p.WaitForExit($WaitSecs * 1000)) { throw "process $id did not exit within $WaitSecs seconds" }
  }
  # Then every other process still running from the install directory (a CLI
  # shell, a worker the gateway left), within the same bound: Windows will not
  # replace an executable or DLL that is still loaded, and a silent installer
  # that skips one leaves a tree of two versions behind.
  $prefix = $InstallDir.TrimEnd('\') + '\'
  while ($true) {
    $busy = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
    if ($busy.Count -eq 0) { break }
    if ((Get-Date) -gt $deadline) { throw "process $(($busy | ForEach-Object { $_.ProcessId }) -join ',') still runs from the install directory" }
    Start-Sleep -Seconds 2
  }
  # The installer that runs is a COPY in a fresh directory whose ACL admits only
  # SYSTEM, Administrators and this account, made read-and-execute only, and
  # checked after that: nothing can rewrite it between the check and the run
  # without first changing its ACL. (Holding the staged file open is no
  # substitute: the installer has to be able to open itself.)
  # The NSIS stub is a 32-bit process, and WOW64 redirects System32 for it, so
  # an installer under System32 (the SYSTEM account's data home is there)
  # cannot open its own file and exits 2. Such a copy goes to the Windows Temp
  # directory instead, still in a locked directory of its own.
  $base = Split-Path -LiteralPath $Installer
  $system = [Environment]::GetFolderPath('System')
  if ($base.StartsWith($system + '\', [StringComparison]::OrdinalIgnoreCase)) {
    $base = Join-Path ([Environment]::GetFolderPath('Windows')) 'Temp'
  }
  $RunDir = Join-Path $base ('kirocrew-update-' + [guid]::NewGuid().ToString('N'))
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $trusted = @('S-1-5-18', 'S-1-5-32-544', $me) | Select-Object -Unique
  New-Item -ItemType Directory -Path $RunDir | Out-Null
  $dacl = New-Object System.Security.AccessControl.DirectorySecurity
  $dacl.SetAccessRuleProtection($true, $false)
  foreach ($sid in $trusted) {
    $who = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $dacl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  }
  Set-Acl -LiteralPath $RunDir -AclObject $dacl
  $run = Join-Path $RunDir ([IO.Path]::GetFileName($Installer))
  Copy-Item -LiteralPath $Installer -Destination $run
  $acl = New-Object System.Security.AccessControl.FileSecurity
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in $trusted) {
    $who = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($who, 'ReadAndExecute', 'Allow')))
  }
  Set-Acl -LiteralPath $run -AclObject $acl
  if ((Get-Item -LiteralPath $run).Length -ne $Size) { throw 'the installer size changed since it was checked' }
  $stream = [System.IO.File]::OpenRead($run)
  try { $got = [Convert]::ToBase64String([System.Security.Cryptography.SHA512]::Create().ComputeHash($stream)) } finally { $stream.Close() }
  if ($got -cne $Sha512) { throw 'the installer does not match the sha512 the release feed names' }
  $sig = Get-AuthenticodeSignature -LiteralPath $run
  if ([string]$sig.Status -ne 'Valid') { throw "the installer's signature is not valid ($($sig.Status))" }
  if (-not $sig.TimeStamperCertificate) { throw "the installer's signature has no timestamp" }
  $signer = $sig.SignerCertificate.GetNameInfo('SimpleName', $false)
  if ($Publishers -notcontains $signer) { throw 'the installer is not signed by the publisher the app pins' }
  Log "verified $Version; running the installer (/S /$Scope)"
  $proc = Start-Process -FilePath $run -ArgumentList '/S', "/$Scope" -PassThru -WindowStyle Hidden
  if (-not $proc.WaitForExit($InstallSecs * 1000)) { throw "the installer did not finish within $InstallSecs seconds" }
  if ($proc.ExitCode -ne 0) { throw "the installer exited with $($proc.ExitCode)" }
  $now = $null
  foreach ($h in 'HKLM:', 'HKCU:') {
    Get-ChildItem "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | ForEach-Object {
      $d = Get-ItemProperty $_.PSPath
      # The entry whose uninstaller sits directly in this install directory, by
      # exact path: a side-by-side install in a sibling directory is another app.
      $u = [string]$d.UninstallString
      $exe = if ($u.StartsWith('"')) { $u.Substring(1).Split('"')[0] } else { ($u -split ' /')[0] }
      $dir = try { [IO.Path]::GetFullPath((Split-Path -Parent $exe.Trim())).TrimEnd('\') } catch { '' }
      if ($d.DisplayName -like 'KiroCrew*' -and $dir -and $dir.Equals($InstallDir.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { $now = $d.DisplayVersion }  # brand-ok
    }
  }
  if ($now -ne $Version) { throw "the installed version is $now, not $Version" }
  Log "installed $Version"
  Finish $true ''
} catch {
  Log "update failed: $_"
  Finish $false ("The update to $Version did not install: " + $_.Exception.Message)
} finally {
  if ($RunDir -and (Test-Path -LiteralPath $RunDir)) {
    try {
      # The copy is read-only to everyone; give the directory's rights back to it so it can go.
      Get-ChildItem -LiteralPath $RunDir -File | ForEach-Object { $a = Get-Acl -LiteralPath $_.FullName; $a.SetAccessRuleProtection($false, $false); Set-Acl -LiteralPath $_.FullName -AclObject $a }
      Remove-Item -LiteralPath $RunDir -Recurse -Force
    } catch { Log "run copy not removed: $_" }
  }
  if ($proc -and -not $proc.HasExited) {
    # The installer outlived its bound and may still be replacing files: a
    # gateway started now would serve from a half-written tree, so it stays
    # stopped and the failure says so.
    Log "the installer is still running; the gateway is not started again"
    Finish $false "The update to $Version did not finish within $InstallSecs seconds; the installer is still running, so the gateway was left stopped."
  } else {
    Restart-Gateway
  }
}
"""


def helper_script(plan: HelperPlan) -> str:
    """The helper's PowerShell, with every value as a quoted literal."""
    header = "\n".join(
        [
            f"$WaitPids = @({','.join(str(int(p)) for p in plan.wait_pids)})",
            f"$Installer = {_ps_literal(plan.installer)}",
            f"$Sha512 = {_ps_literal(plan.sha512)}",
            f"$Size = {int(plan.size)}",
            f"$Publishers = {_ps_array(plan.publishers)}",
            f"$Version = {_ps_literal(plan.version)}",
            f"$Scope = {_ps_literal(plan.scope)}",
            f"$InstallDir = {_ps_literal(plan.install_dir)}",
            f"$ResultPath = {_ps_literal(plan.result_path)}",
            f"$LogPath = {_ps_literal(plan.log_path)}",
            f"$RestartArgv = {_ps_array(plan.restart_argv)}",
            f"$RestartCwd = {_ps_literal(plan.restart_cwd or plan.install_dir)}",
            f"$GatewayOutput = {_ps_literal(plan.gateway_output)}",
            f"$WaitSecs = {HELPER_WAIT_EXIT_SECS}",
            f"$InstallSecs = {HELPER_INSTALL_SECS}",
        ]
    )
    if plan.restart_argv:
        if not plan.gateway_output:
            raise ValueError("a restarting helper needs somewhere for the gateway's output")
        for arg in plan.restart_argv:
            # Quoted and joined by the helper: a quote, or a backslash right
            # before the closing quote, would split or merge arguments.
            if not arg or arg.endswith("\\") or _UNSAFE_ARG_RE.search(arg):
                raise ValueError(f"unsafe argument for the gateway command line: {arg!r}")
    if plan.scope not in (SCOPE_ALL_USERS, SCOPE_CURRENT_USER):
        raise ValueError(f"unknown install scope {plan.scope!r}")
    return header + "\n" + _HELPER_BODY


def helper_argv(plan: HelperPlan) -> list[str]:
    """The helper's command line: the script travels encoded, never as a file.

    A script file in a directory the agent can write could be edited between the
    write and the run; an ``-EncodedCommand`` cannot.
    """
    encoded = base64.b64encode(helper_script(plan).encode("utf-16-le")).decode("ascii")
    return [
        _powershell(),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-EncodedCommand",
        encoded,
    ]


def _spawn_detached(argv: list[str]) -> int:
    """Start *argv* so it outlives this process; return its pid."""
    # A hidden console, not DETACHED_PROCESS: Windows PowerShell started with no
    # console at all exits 0 without running its command (measured on Windows
    # Server 2022), which would look like a hand-off that silently did nothing.
    flags = 0
    for name in ("CREATE_NEW_PROCESS_GROUP", "CREATE_NO_WINDOW"):
        flags |= int(getattr(subprocess, name, 0))
    breakaway = int(getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0))
    kwargs: dict[str, Any] = dict(
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        # Out of the job a service manager may hold the gateway in, so stopping
        # that job does not stop the installer half-way.
        proc = subprocess.Popen(argv, creationflags=flags | breakaway, **kwargs)
    except OSError:
        proc = subprocess.Popen(argv, creationflags=flags, **kwargs)
    return proc.pid


def restart_argv() -> tuple[str, ...]:
    """The command that starts this gateway again as it was started."""
    from kiro_crew.platform_compat import isolated_python_argv

    return tuple(isolated_python_argv("-P", "-m", "kiro_crew", *sys.argv[1:]))


def _gateway_output() -> str:
    from kiro_crew.config.paths import data_home

    return str(data_home() / GATEWAY_OUTPUT)


def _result_path() -> Path:
    from kiro_crew.config.paths import data_home

    return data_home() / RESULT_FILE


def read_result() -> dict[str, Any] | None:
    """The helper's last result record, or ``None``."""
    try:
        data = json.loads(_result_path().read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def clear_result() -> None:
    _unlink_quietly(_result_path())


@dataclass(frozen=True)
class Prepared:
    """A staged, verified installer and the facts the hand-off needs."""

    release: FeedRelease
    installer: Path
    publishers: tuple[str, ...]
    scope: str
    root: Path


async def prepare(
    running_version: str,
    *,
    expected_version: str | None = None,
    download: Downloader = _download,
    signature_reader: Callable[[Path], dict[str, Any]] = read_signature,
    scope_entries: Callable[[], list[tuple[str, str, str]]] = _uninstall_entries,
    is_admin: Callable[[], bool] = _is_admin,
) -> Prepared:
    """Check the feed, then stage and verify the installer. Raises on any refusal.

    *expected_version* is the version a person armed: the feed must still offer
    exactly it, so a channel switch or a feed change after the arm installs
    nothing the person was not shown.
    """
    if not _on_windows():
        raise DesktopUpdateError(ERR_NOT_WINDOWS, "This update path runs on Windows only.")
    root = await asyncio.to_thread(install_dir)
    if root is None:
        raise DesktopUpdateError(ERR_NO_INSTALL, "The desktop install directory was not found.")
    refusal = await asyncio.to_thread(source_refusal)
    if refusal:
        raise DesktopUpdateError(ERR_SOURCE, refusal)
    channel = await asyncio.to_thread(desktop_channel, running_version)
    if channel is None:
        raise DesktopUpdateError(ERR_FEED, "This install follows no desktop release channel.")
    publishers = await asyncio.to_thread(pinned_publishers, root)
    scope = await asyncio.to_thread(lambda: install_scope(root, entries=scope_entries))
    require_rights(scope, is_admin=is_admin)
    release = await fetch_feed(channel)
    if expected_version is not None and release.version != expected_version:
        raise DesktopUpdateError(
            ERR_VERSION_CHANGED,
            f"The release feed now offers {release.version}, not the {expected_version} "
            "that was armed. Check for updates again.",
        )
    require_newer(release, running_version)
    installer = await stage(
        release, publishers, download=download, signature_reader=signature_reader
    )
    return Prepared(release, installer, publishers, scope, root)


def hand_off(
    prepared: Prepared,
    *,
    wait_pids: tuple[int, ...],
    restart: bool,
    spawn: Callable[[list[str]], int] = _spawn_detached,
) -> int:
    """Start the helper for *prepared*; return its pid. The caller then exits."""
    from kiro_crew.config.paths import data_home

    clear_result()
    plan = HelperPlan(
        wait_pids=wait_pids,
        installer=str(prepared.installer),
        sha512=prepared.release.sha512,
        size=prepared.release.size,
        publishers=prepared.publishers,
        version=prepared.release.version,
        scope=prepared.scope,
        install_dir=str(prepared.root),
        result_path=str(_result_path()),
        log_path=str(data_home() / HELPER_LOG),
        restart_argv=restart_argv() if restart else (),
        restart_cwd=os.getcwd() if restart else "",
        gateway_output=_gateway_output() if restart else "",
    )
    pid = spawn(helper_argv(plan))
    logger.info(
        "Desktop update %s handed to installer helper pid %d (waits for %s)",
        prepared.release.version,
        pid,
        ",".join(str(p) for p in wait_pids),
    )
    return pid


def result_error_for(version: str) -> str | None:
    """The helper's failure for *version*, or ``None`` when it did not fail for it."""
    result = read_result()
    if not result or result.get("version") != version or result.get("ok") is True:
        return None
    error = result.get("error")
    return error if isinstance(error, str) and error else "The desktop update did not install."


__all__ = [
    "DESKTOP_CHANNELS",
    "DesktopUpdateError",
    "FeedRelease",
    "HelperPlan",
    "Prepared",
    "desktop_channel",
    "fetch_feed",
    "hand_off",
    "headless_desktop_install",
    "helper_argv",
    "helper_script",
    "install_dir",
    "install_scope",
    "parse_feed",
    "pinned_publishers",
    "prepare",
    "require_newer",
    "result_error_for",
    "source_overridden",
    "source_refusal",
    "stage",
    "verify_digest",
    "verify_signature",
]

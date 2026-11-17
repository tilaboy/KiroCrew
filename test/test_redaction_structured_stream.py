"""Stream/whole parity and linear-time tests for the structured credential detector."""

from __future__ import annotations

import random
from collections.abc import Callable, Iterator

import pytest
from redaction_structured_cases import (
    B64,
    PEM_BEGIN,
    PEM_BEGIN_PLAIN,
    PEM_BODY,
    PEM_END,
    PGP_BEGIN,
    PGP_END,
    assert_linear_work,
    aws_key_id,
    aws_secret,
    benign_cases,
    github_classic,
    jwt,
    secret_cases,
    session_token,
    synth,
)

from kiro_crew.security.redaction_structured import TAG, StreamRedactor, redact
from kiro_crew.security.redaction_structured.stream import CONTEXT

ALL_TEXTS = [(n, t) for n, t, _, _ in secret_cases()] + benign_cases()
ALL_TEXTS += [
    ("mixed", "\n".join(t for _, t in ALL_TEXTS[:12])),
    ("pair_across", f"{aws_secret()} " + "y" * 250 + f" {aws_key_id()} tail text"),
]


def run_stream(chunks: list[str]) -> tuple[str, list[tuple[int, int, str, str]]]:
    s = StreamRedactor()
    out = "".join(s.feed(c) for c in chunks) + s.flush()
    return out, s.spans


def split_at(text: str, cuts: list[int]) -> list[str]:
    bounds = [0, *sorted(cuts), len(text)]
    return [text[a:b] for a, b in zip(bounds, bounds[1:], strict=False)]


@pytest.mark.parametrize("text", [pytest.param(t, id=n) for n, t in ALL_TEXTS])
def test_chunked_equals_whole_at_every_split_point(text: str) -> None:
    whole = redact(text)
    for cut in range(len(text) + 1):
        assert run_stream([text[:cut], text[cut:]]) == whole, f"split at {cut}"


@pytest.mark.parametrize("text", [pytest.param(t, id=n) for n, t in ALL_TEXTS])
def test_chunked_equals_whole_at_random_multi_splits(text: str) -> None:
    whole = redact(text)
    rng = random.Random(len(text))
    for _ in range(25):
        cuts = [rng.randrange(len(text) + 1) for _ in range(rng.randrange(2, 12))]
        assert run_stream(split_at(text, cuts)) == whole, cuts


@pytest.mark.parametrize("text", [pytest.param(t, id=n) for n, t in ALL_TEXTS[:20]])
def test_one_character_feeds(text: str) -> None:
    assert run_stream(list(text)) == redact(text)


def _long_cases() -> list[tuple[str, str]]:
    sess = session_token(6000, seed=7)
    return [
        ("pem_past_max_block", f"a {PEM_BEGIN}\n" + "B" * 17000 + "\nafter " * 20),
        ("pgp_unterminated_long", f"{PGP_BEGIN}\n" + PEM_BODY * 300),
        ("session_run_fail_closed", f"AWS_SESSION_TOKEN={sess}=\nnext {github_classic()}"),
        ("session_run_padded", f'{{"SessionToken": "{sess}=="}} ok'),
        ("long_jose_run", "eyJ" + "A" * 20000 + " " + jwt()),
        ("long_benign", ("plain words, a://b and arn:aws:s3:::bkt " * 600)),
        ("context_reach", "x" * (CONTEXT * 3) + f" {aws_key_id()} {aws_secret()}"),
    ]


@pytest.mark.parametrize("text", [pytest.param(t, id=n) for n, t in _long_cases()])
def test_long_units_match_whole_text(text: str) -> None:
    whole = redact(text)
    step = max(1, len(text) // 300)
    for cut in range(0, len(text) + 1, step):
        assert run_stream([text[:cut], text[cut:]]) == whole, f"split at {cut}"
    rng = random.Random(7)
    for _ in range(10):
        cuts = [rng.randrange(len(text) + 1) for _ in range(rng.randrange(5, 40))]
        assert run_stream(split_at(text, cuts)) == whole
    assert run_stream([text[i : i + 997] for i in range(0, len(text), 997)]) == whole


def test_session_run_tail_is_discarded_not_resumed() -> None:
    sess = session_token(9000, seed=3)
    text = f"AWS_SESSION_TOKEN={sess}\nafter"
    s = StreamRedactor()
    pieces = [s.feed(text[i : i + 512]) for i in range(0, len(text), 512)]
    out = "".join(pieces) + s.flush()
    assert out == f"AWS_SESSION_TOKEN={TAG}\nafter"
    assert sess[-50:] not in out


def test_pending_text_stays_bounded() -> None:
    s = StreamRedactor()
    longest = 0
    rng = random.Random(1)
    corpus = [t for _, t in ALL_TEXTS] + ["word " * 50, synth(400, B64, 3), "eyJ" + "Q" * 3000]
    for _ in range(400):
        s.feed(rng.choice(corpus) + "\n")
        longest = max(longest, len(s._pending))  # noqa: SLF001
    s.flush()
    # The largest hold is a private-key block (16,000 plus its END line) or a JOSE run.
    assert longest < 20_000


@pytest.mark.parametrize("unit", ["x", "X", "*"])
def test_a_mask_run_fed_in_pieces_is_not_held_past_its_bound(unit: str) -> None:
    s = StreamRedactor()
    longest = 0
    for _ in range(64):
        s.feed(unit * 4096)
        longest = max(longest, len(s._pending))  # noqa: SLF001
    s.flush()
    assert longest < 20_000


@pytest.mark.parametrize("chunk", [1, 7, 256, 1024, 4097])
@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("gap", [1500, 3000])
def test_a_session_cookie_past_the_look_behind_from_its_header_is_masked(
    entry: str, chunk: int, gap: int
) -> None:
    # The pair sits further from ``Cookie:`` than the stream's look-behind reaches,
    # so a window that starts after the header name cannot read it again.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    value = synth(48, B64, 11)
    text = f"Cookie: theme={'a' * gap}; session={value}\nafter"
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = "".join(s.feed(text[i : i + chunk]) for i in range(0, len(text), chunk)) + s.flush()
    assert value not in out
    assert out.endswith(f"session={TAG}\nafter")


def _benign_cookie_line(length: int) -> str:
    """``Cookie: a=1; a=1; ...`` cut to *length* characters, with no line end."""
    return ("Cookie: " + "a=1; " * (length // 5 + 1))[:length]


def test_a_running_cookie_line_holds_only_its_open_pair() -> None:
    from kiro_crew.security.redaction_structured.stream import TAIL

    line = _benign_cookie_line(10_008)
    s = StreamRedactor()
    out, longest = "", 0
    for i in range(0, len(line), 64):
        out += s.feed(line[i : i + 64])
        longest = max(longest, len(s._pending))  # noqa: SLF001
    out += s.feed("\nafter") + s.flush()
    assert longest <= TAIL + 64
    assert out == line + "\nafter"


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_cookie_line_in_small_feeds_scans_linear_work(
    entry: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Each scan reads the look-behind and the new text, never the whole held line:
    # an 8 KiB Cookie line in 4-character feeds is never scanned past 2 * CONTEXT.
    from kiro_crew.security.redaction_structured import engine, stream

    scanned: list[int] = []
    real = engine.scan

    def counting(text: str, *args: object, **kwargs: object) -> object:
        scanned.append(len(text))
        return real(text, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(engine, "scan", counting)
    monkeypatch.setattr(stream, "scan", counting)
    s, _ = _redactor(entry)
    line = ("Cookie: " + ";".join(f"k{i}=v" for i in range(2000)))[:8192]
    feeds = range(0, len(line), 4)
    for i in feeds:
        s.feed(line[i : i + 4])  # type: ignore[attr-defined]
    s.feed("\n")  # type: ignore[attr-defined]
    s.flush()  # type: ignore[attr-defined]
    assert len(scanned) >= len(feeds)
    assert max(scanned) <= 2 * stream.CONTEXT


def test_a_flush_inside_a_line_drop_closes_the_span_past_the_carried_tail() -> None:
    # The span covers all dropped input; the redacted text never carried the tail.
    s = StreamRedactor()
    out = s.feed("Cookie: " + "a" * 8184) + s.feed("b" * 500) + s.flush()
    assert "b" not in out
    assert [sp[:2] for sp in s.spans] == [(8, 8692)]


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_only_a_session_pair_at_its_bound_is_masked(entry: str) -> None:
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor
    from kiro_crew.security.redaction_structured.headers import COOKIE_LINE_HOLD

    def run(line: str) -> str:
        s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
        return "".join(s.feed(c) for c in (line, "\nafter")) + s.flush()

    # A benign line is never held, so it reads as the whole text at any length.
    for length in (COOKIE_LINE_HOLD - 1, COOKIE_LINE_HOLD, COOKIE_LINE_HOLD + 1, 20_000):
        line = _benign_cookie_line(length)
        assert run(line) == redact(line + "\nafter")[0] == line + "\nafter"

    # A session pair is held from its start for at most COOKIE_LINE_HOLD characters;
    # one still running at the bound has the rest of its line masked.
    def session_line(pair: int) -> str:
        return "Cookie: session=" + "a" * (pair - len("session="))

    short = session_line(COOKIE_LINE_HOLD - 1)
    assert run(short) == redact(short + "\nafter")[0]
    assert run(session_line(COOKIE_LINE_HOLD)) == f"Cookie: session={TAG}\nafter"
    assert run(session_line(COOKIE_LINE_HOLD + 1)) == f"Cookie: session={TAG}\nafter"


def _token_overflow_line(name: str, session: str) -> str:
    return (
        f"{name}: theme={'a' * 750}; url=https://h.test/p?token={'b' * 3500}"
        f"; session={session}\nafter"
    )


def _feed_in(redactor: object, text: str, chunk: int) -> str:
    """Feed *text* in *chunk*-sized pieces. Every hold is bounded (a session pair at
    COOKIE_LINE_HOLD, the look-behind at CONTEXT), so a buffer past their sum is the
    unbounded hold this stream must not keep: it fails here, at once, instead of after
    a rescan of the whole held text on every later feed."""
    from kiro_crew.security.redaction_structured.headers import COOKIE_LINE_HOLD

    feed = redactor.feed  # type: ignore[attr-defined]
    held = "_pending" if hasattr(redactor, "_pending") else "_buf"
    budget = COOKIE_LINE_HOLD + 2 * CONTEXT + chunk
    out = []
    for i in range(0, len(text), chunk):
        out.append(feed(text[i : i + chunk]))
        assert len(getattr(redactor, held, "")) <= budget, "unbounded hold"
    return "".join(out) + redactor.flush()  # type: ignore[attr-defined]


@pytest.mark.parametrize("chunk", [1, 7, 128, 1024])
def test_a_token_overflow_inside_an_open_cookie_line_masks_through_its_end(chunk: int) -> None:
    # The 4096-character token ceiling fires while the Cookie line is held from its
    # name; dropping only the token run would release the session pair after it.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    value = synth(48, B64, 13)
    text = _token_overflow_line("Cookie", value)
    out = _feed_in(ProductionStreamRedactor(), text, chunk)
    assert value not in out
    assert out.endswith(f"{TAG}\nafter")
    assert value not in redact(text)[0]
    assert value not in run_stream([text])[0]


@pytest.mark.parametrize("chunk", [1, 7, 128, 1024])
def test_a_cookie_header_after_an_overflowing_token_keeps_its_line(chunk: int) -> None:
    # Only a Cookie name before the dropped credential widens the drop; a Cookie
    # header after it is read on its own and keeps its benign text.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    value = synth(48, B64, 19)
    text = f"X: token={'b' * 4300}; Cookie: theme={'a' * 2000}; session={value}\nafter"
    out = _feed_in(ProductionStreamRedactor(), text, chunk)
    assert value not in out
    assert out.endswith(f"theme={'a' * 2000}; session={TAG}\nafter")


@pytest.mark.parametrize("chunk", [1, 7, 128, 1024])
@pytest.mark.parametrize(
    "head, close",
    [
        pytest.param('{"Cookie": "', '"}', id="json-quoted"),
        pytest.param("Cookie\u00a0:\u2003", "", id="unicode-spaced"),
        pytest.param("Cookie: ", "", id="plain"),
        pytest.param("Cook\u0131e: ", "", id="dotless-i"),
    ],
)
def test_a_token_overflow_in_any_cookie_spelling_masks_through_its_end(
    head: str, close: str, chunk: int
) -> None:
    # The open-line check reads the Cookie name with the cookie reader's grammar,
    # so every spelling that reader holds is also dropped through its line end.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    value = synth(48, B64, 23)
    body = f"theme={'a' * 750}; url=https://h.test/p?token={'b' * 3500}; session={value}"
    text = f"{head}{body}{close}\nafter"
    out = _feed_in(ProductionStreamRedactor(), text, chunk)
    assert value not in out
    assert out.endswith("\nafter")
    assert value not in redact(text)[0]
    assert value not in _feed_in(StreamRedactor(), text, chunk)


def test_a_token_overflow_outside_a_cookie_line_drops_only_the_run() -> None:
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    text = _token_overflow_line("X-Note", "plainword")
    out = _feed_in(ProductionStreamRedactor(), text, 128)
    head = f"X-Note: theme={'a' * 750}; url=https://h.test/p?token="
    assert out == f"{head}{TAG}; session=plainword\nafter"


def test_a_set_cookie_response_streams_without_spinning() -> None:
    import threading

    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor
    from kiro_crew.testing.wait import default_timeout

    text = (
        "HTTP/1.1 302 Found\nLocation: /dashboard\n"
        f"Set-Cookie: session={synth(40, B64, 17)}; Path=/; HttpOnly\n\nbody"
    )
    result: list[str] = []
    worker = threading.Thread(
        target=lambda: result.append(_feed_in(ProductionStreamRedactor(), text, 1)), daemon=True
    )
    worker.start()
    worker.join(default_timeout())
    assert result, "the stream did not finish a one-character feed of a Set-Cookie response"
    assert result[0].count(TAG) == 1


@pytest.mark.parametrize("head", ["Cookie : ", "Cookie = ", '"Cookie" : ', "cookie\u2003:\u2003"])
@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_cookie_name_held_while_its_separator_is_still_to_come(entry: str, head: str) -> None:
    # Fed one character at a time, the name arrives before its separator: the
    # name is held until the separator decides it, so later pairs still read it.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    value = synth(48, B64, 37)
    text = f"{head}{'x=y; ' * 1700}session={value}\nafter"
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = "".join(s.feed(ch) for ch in text[:3000]) + s.feed(text[3000:]) + s.flush()
    assert value not in out
    assert out.endswith("\nafter")


def test_a_closed_credential_over_the_ceiling_in_a_cookie_line_keeps_the_line() -> None:
    # The token ceiling fires on a Cookie line whose credential has already closed:
    # the drop still runs to the line end, so the header name is not lost.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor
    from kiro_crew.testing.synthetic_credentials import aws_secret

    value = synth(48, B64, 41)
    head = f"Cookie: theme={'a' * 4100} \"SessionToken\": \"{aws_secret()}\""
    s = ProductionStreamRedactor()
    out = s.feed(head) + s.feed(f"; session={value}\nafter") + s.flush()
    assert value not in out
    assert out.endswith("\nafter")
    assert value not in redact(f"{head}; session={value}\nafter")[0]


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 4096])
def test_a_cookie_separator_past_its_bound_masks_the_line(entry: str, chunk: int) -> None:
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    value = synth(48, B64, 43)
    text = f"Cookie{' ' * 65}: theme={'a' * 1500}; session={value}\nafter"
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = _feed_in(s, text, chunk)
    assert value not in out
    assert out.endswith("\nafter")
    assert value not in redact(text)[0]


def _cookie_line_with_open_key(lead: str) -> tuple[str, str]:
    from redaction_structured_cases import PEM_BEGIN

    end = PEM_BEGIN.replace("BEGIN", "END")
    body = synth(96, B64, 47)
    text = f"Cookie: theme={lead}{PEM_BEGIN}{'A' * 8200}\n{body}\n{end}\nafter"
    return text, body


@pytest.mark.parametrize("chunk", [1024, 4096])
@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("lead", ["", "a" * 3000], ids=["key-at-value", "key-inside-run"])
def test_a_cookie_line_drop_waits_for_a_private_key_block_opened_on_it(
    lead: str, entry: str, chunk: int
) -> None:
    # The 8 KiB Cookie cap drops to the line end; a private-key block opened on that
    # line is still undecided there, so the drop waits for it (bounded by the block's
    # own limit) instead of losing its BEGIN line and streaming the key body.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    text, body = _cookie_line_with_open_key(lead)
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = _feed_in(s, text, chunk)
    assert body[:24] not in out
    assert out == redact(text)[0]


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_long_cookie_line_fed_under_its_bound_reads_as_the_whole_text(entry: str) -> None:
    # Decided pairs commit while the look-behind keeps the name, so no window reads
    # the line 8 KiB past its name: the stream leaves it as the whole text does.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    line = _benign_cookie_line(10_008)
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = _feed_in(s, line + "\nafter", 1024)
    assert out == redact(line + "\nafter")[0] == line + "\nafter"


def _hex_ids_cookie_line(size: int) -> str:
    """``Cookie: ids=`` and comma-joined 40-hex ids to *size*, no LF:
    every id is a candidate the key pairing reads."""
    import hashlib

    ids = [hashlib.sha256(str(i).encode()).hexdigest()[:40] for i in range(size // 41 + 1)]
    return ("Cookie: ids=" + ",".join(ids))[:size]


def _redactor(entry: str) -> tuple[object, str]:
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    if entry == "structured":
        return StreamRedactor(), "_pending"
    return ProductionStreamRedactor(), "_buf"


def _key_rows(count: int, seed: int) -> list[str]:
    return [synth(64, B64, seed + k) for k in range(count)]


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_an_unterminated_key_opened_during_the_drop_masks_to_the_end(entry: str) -> None:
    # GPT's trigger: the block's BEGIN leaves the look-behind and no END arrives
    # inside its bound, so the drop switches to the end of the text, as whole-text
    # armour reads an unterminated block, instead of ending at a deadline.
    from redaction_structured_cases import PEM_BEGIN

    lines = _key_rows(280, 300)
    text = f"Cookie: session={'a' * 13000}{PEM_BEGIN}\n" + "\n".join(lines)
    s, _ = _redactor(entry)
    out = _feed_in(s, text, 1024)
    whole = redact(text)[0]
    assert not any(line[:24] in whole for line in lines)
    assert not any(line[:24] in out for line in lines)
    assert out == f"Cookie: session={TAG}"


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_an_end_line_past_sixteen_thousand_from_the_begin_is_honoured(entry: str) -> None:
    # Opus's second case: the END starts past BEGIN + 16,000 but inside the block's
    # own bound (header end + max_block + END line), so it closes the block.
    from redaction_structured_cases import PEM_BEGIN

    end = PEM_BEGIN.replace("BEGIN", "END")
    head = f"{PEM_BEGIN}\n"
    rows, size = [], len(head)
    k = 0
    while size < 16_010:
        rows.append(synth(64, B64, 600 + k))
        size += 65
        k += 1
    body = "\n".join(rows)
    text = f"Cookie: session={'a' * 13000}{head}{body}\n{end}\nAFTERLINE visible\n"
    begin = text.index(PEM_BEGIN)
    assert text.index(end, begin) - begin > 16_000
    s, _ = _redactor(entry)
    out = _feed_in(s, text, 1024)
    # Nothing of the body is released: the drop runs to and through the END line.
    assert out == f"Cookie: session={TAG}{end}\nAFTERLINE visible\n"
    whole = redact(text)[0]
    assert whole.endswith(f"{end}\nAFTERLINE visible\n")


def test_completed_keys_on_one_dropped_line_stream_in_linear_work() -> None:
    # Each completed block folds into one furthest end; only open blocks are kept,
    # so blocks on one dropped line cost the same per byte however many there are.
    from redaction_structured_cases import PEM_BEGIN, package_lines

    end = PEM_BEGIN.replace("BEGIN", "END")
    block = f"{PEM_BEGIN}{synth(40, B64, 900)}{end} "

    def per_byte(entry: str, count: int) -> float:
        text = f"Cookie: session={'a' * 13000}" + block * count + "\nafter"

        def run() -> None:
            s, _ = _redactor(entry)
            _feed_in(s, text, 1024)

        return package_lines(run) / len(text)

    def most_kept(entry: str, count: int) -> int:
        # The records the drop keeps, at their largest while the line runs. The line
        # counter cannot see a C-level max() over a growing dict, so this is the pin
        # on what the drop retains.
        text = f"Cookie: session={'a' * 13000}" + block * count
        s, _ = _redactor(entry)
        most = 0
        for i in range(0, len(text), 1024):
            s.feed(text[i : i + 1024])  # type: ignore[attr-defined]
            drop = getattr(s, "_line_drop" if entry == "structured" else "_engine_line")
            if drop is not None:
                kept = (getattr(drop, n) for n in type(drop).__slots__)
                most = max(most, sum(len(v) for v in kept if isinstance(v, dict)))
        return most

    for entry in ("structured", "production"):
        rates = [per_byte(entry, count) for count in (250, 500, 1000)]
        assert all(b <= a * 2.2 for a, b in zip(rates, rates[1:])), (entry, rates)
        assert most_kept(entry, 1000) <= 1


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_begin_split_across_feeds_that_proves_false_holds_nothing(entry: str) -> None:
    # A chunk ends inside what could be a BEGIN line; the next feed shows it is not
    # one, so it is dropped as a candidate and the following line streams.
    s, _ = _redactor(entry)
    line = f"Cookie: session={'a' * 13000}"
    out = "".join(s.feed(line[i : i + 1024]) for i in range(0, len(line), 1024))  # type: ignore[attr-defined]
    out += s.feed("-----BEGIN RSA PRIV")  # type: ignore[attr-defined]
    out += s.feed("ATE KEX nonsense\nAFTERLINE visible\n")  # type: ignore[attr-defined]
    out += s.flush()  # type: ignore[attr-defined]
    assert out == f"Cookie: session={TAG}\nAFTERLINE visible\n"


_GLUED_HEAD = "-----BEGIN RSA " "PRIVATE KEY-----" "END RSA " "PRIVATE KEY-----"
_GLUED_ROWS = [f"SECRETROW{k:03d}" + synth(52, B64, 700 + k) for k in range(40)]
_GLUED_CASES = {
    "unterminated_LF": "\n".join([_GLUED_HEAD, *_GLUED_ROWS, "TAIL visible\n"]),
    "unterminated_CR": "\r".join([_GLUED_HEAD, *_GLUED_ROWS, "TAIL visible\r"]),
    "terminated_LF": "\n".join(
        [_GLUED_HEAD, *_GLUED_ROWS, "-----END RSA " "PRIVATE KEY-----", "TAIL visible\n"]
    ),
}


@pytest.mark.parametrize("chunk", [1, 7, 48, 1024, 4097])
@pytest.mark.parametrize("case", sorted(_GLUED_CASES))
@pytest.mark.parametrize("entry", ["structured", "production"])
def test_an_end_line_glued_to_the_begin_header_does_not_close_the_drop(
    entry: str, case: str, chunk: int
) -> None:
    # The header's closing dashes also open an END line; the drop searches the END
    # from the header end, where whole-text armour does, so that text is not one.
    text = f"Cookie: session={'a' * 13000}" + _GLUED_CASES[case]
    s, _ = _redactor(entry)
    out = _feed_in(s, text, chunk)
    whole = redact(text)[0]
    assert not any(row[:12] in whole for row in _GLUED_ROWS)
    # From the key on, the stream equals the whole text up to the line break at the
    # drop's edge; before it, the stream masks the over-8-KiB Cookie run the whole
    # text keeps (the documented exception).
    assert out.startswith(f"Cookie: session={TAG}")
    rest = whole[whole.rindex(TAG) + len(TAG) :]
    assert out[len(f"Cookie: session={TAG}") :].strip("\r\n") == rest.strip("\r\n")


def _ceiling_key_text(nl: str, body_len: int) -> tuple[str, str, str]:
    """GPT's trigger: a Cookie line past the token ceiling with a key block on it;
    the ceiling fires at the Bearer token after the key body."""
    from redaction_structured_cases import PEM_BEGIN

    end = PEM_BEGIN.replace("BEGIN", "END")
    body = synth(body_len, B64, 41)
    row = "ROWSECRET" + synth(55, B64, 43)
    text = (
        "Cookie: "
        + "a=1; " * 800
        + PEM_BEGIN
        + body
        + " Authorization: Bearer "
        + synth(48, B64, 45)
        + nl
        + row
        + nl
        + end
        + nl
        + "after visible"
        + nl
    )
    return text, body, row


# No chunk 1: CI's per-test cap is 120 s, and at one character per feed the line
# drop rescans the 1 KiB look-behind each time, about 1 KiB of work per character
# (47.66 s locally on the production lane, 24.27 s on the structured lane). The
# mutant restoring the late construction reddens at chunks 7 and 48, so chunk 1
# adds no proof power.
@pytest.mark.parametrize("chunk", [7, 48, 1024, 4097])
@pytest.mark.parametrize("nl", ["\n", "\r"], ids=["LF", "CR"])
@pytest.mark.parametrize("body_len", [900, 1100, 1500], ids=["inside", "outside", "lane"])
@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_key_on_a_cookie_line_past_the_token_ceiling_is_carried_to_its_end(
    entry: str, body_len: int, nl: str, chunk: int
) -> None:
    # The token ceiling arms the line drop over a window larger than the look-behind;
    # the drop reads that window before it is dropped, so a BEGIN anywhere on the
    # line (900 / 1100 characters before the cut sit inside / outside the 1 KiB
    # look-behind) is carried to its END and the row after the line stays masked.
    text, body, row = _ceiling_key_text(nl, body_len)
    whole = redact(text)[0]
    assert row[:12] not in whole and body[:20] not in whole
    s, _ = _redactor(entry)
    out = _feed_in(s, text, chunk)
    assert row[:12] not in out and body[:20] not in out
    assert out.endswith(f"{nl}after visible{nl}")


@pytest.mark.parametrize("chunk", [7, 512, 4097])
@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_bearer_value_after_a_long_blank_run_on_a_cookie_line_is_not_covered_yet(
    entry: str, chunk: int
) -> None:
    # Not covered (main's own): after more blanks than the 1 KiB look-behind,
    # a Bearer value on the next line is released by main's streams with or without
    # a Cookie line before it, at every chunk here. This PR never releases more than
    # main; the row flips once main reads that value.
    token = synth(40, B64, 77)
    text = f"Cookie: session={'a' * 13000} Authorization: Bearer{' ' * 1100}\n{token}\nafter\n"
    assert token not in redact(text)[0]
    s, _ = _redactor(entry)
    assert token in _feed_in(s, text, chunk)


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_long_cookie_line_of_pairing_candidates_reads_as_the_whole_text(entry: str) -> None:
    # A pairing open never holds the drop: only a private-key block can decide text
    # past the line end. Holding on any open kept this line whole and rescanned it.
    text = _hex_ids_cookie_line(20_000) + "\nafter"
    s, pending = _redactor(entry)
    out, longest = "", 0
    for i in range(0, len(text), 1024):
        out += s.feed(text[i : i + 1024])  # type: ignore[attr-defined]
        longest = max(longest, len(getattr(s, pending)))
    out += s.flush()  # type: ignore[attr-defined]
    assert longest < 8 << 10, longest
    # A benign ``ids=`` value is never held, so the line reads as the whole text.
    assert out == redact(text)[0]


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_chunk_ending_inside_a_short_run_on_a_long_cookie_line_reads_as_whole(
    entry: str,
) -> None:
    line = _benign_cookie_line(9_000) + "; v=ab12cd34ef"
    cut = len(line) - 6
    s, _ = _redactor(entry)
    out = s.feed(line[:cut]) + s.feed(line[cut:] + "\nafter") + s.flush()  # type: ignore[attr-defined]
    assert out == redact(line + "\nafter")[0]


def test_a_long_cookie_line_of_pairing_candidates_streams_in_linear_work() -> None:
    from redaction_structured_cases import package_lines

    def per_byte(entry: str, size: int) -> float:
        text = _hex_ids_cookie_line(size) + "\nafter"

        def run() -> None:
            s, _ = _redactor(entry)
            for i in range(0, len(text), 1024):
                s.feed(text[i : i + 1024])  # type: ignore[attr-defined]
            s.flush()  # type: ignore[attr-defined]

        return package_lines(run) / size

    # Work per byte stays flat: within 2.2x across 16, 32 and 64 KiB, counted in
    # executed lines. Holding on every open rescanned the line, so the rate grew
    # about 1.85x per doubling (3.4x across the range).
    for entry in ("structured", "production"):
        rates = [per_byte(entry, size) for size in (16 << 10, 32 << 10, 64 << 10)]
        assert max(rates) <= min(rates) * 2.2, (entry, rates)


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_pairing_split_by_the_line_drop_masks_no_less_than_the_whole_text(
    entry: str,
) -> None:
    # The key id is dropped with the line; its secret on the next line is scanned
    # as usual, so the stream masks at least what the whole text masks.
    from redaction_structured_cases import aws_key_id, aws_secret

    key_id, secret = aws_key_id(), aws_secret()
    text = f"Cookie: session={'a' * 13000} {key_id}\n{secret}\nafter"
    s, _ = _redactor(entry)
    out = _feed_in(s, text, 1024)
    assert secret not in redact(text)[0]
    assert out == f"Cookie: session={TAG}\n{TAG}\nafter"


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_scheme_value_after_a_long_blank_run_is_not_covered_yet(entry: str) -> None:
    # Not covered by this stream: a scheme value on the next line after more blanks
    # than the stream's look-behind keeps loses its scheme, with or without a Cookie
    # line before it. This row records today's verdict so a change that widens the gap
    # shows; it flips once that gap is fixed.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    token = synth(32, B64, 53)
    text = f" Authorization: Bearer{' ' * 1100}\n{token}\nafter"
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    assert token not in redact(text)[0]
    # The production stream's own Bearer anchor still masks it; the structured
    # stream alone releases it.
    assert (token in _feed_in(s, text, 512)) == (entry == "structured")


def _key_after_cookie_run(split: bool = False) -> tuple[list[str], str, str]:
    """GPT's trigger: a private-key block that opens after the 8 KiB drop began."""
    from redaction_structured_cases import PEM_BEGIN

    end = PEM_BEGIN.replace("BEGIN", "END")
    body = synth(1100, B64, 59)
    more = synth(64, B64, 61)
    text = f"Cookie: session={'a' * 13000}{PEM_BEGIN}{body}\n{more}\n{end}\nafter"
    if not split:
        return [text[i : i + 1024] for i in range(0, len(text), 1024)], body, more
    # Two chunks, cut inside the BEGIN marker.
    cut = text.index(PEM_BEGIN) + 7
    return [text[:cut], text[cut:]], body, more


@pytest.mark.parametrize("split", [False, True], ids=["chunks", "split-marker"])
@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_key_opened_during_a_cookie_line_drop_is_carried_through(entry: str, split: bool) -> None:
    # A private-key block that opens after the line drop began is read during the
    # drop (never emitted), and the drop runs through the block's own end instead of
    # stopping at the line end with the BEGIN line already gone.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    chunks, body, more = _key_after_cookie_run(split)
    text = "".join(chunks)
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = "".join(s.feed(c) for c in chunks) + s.flush()
    assert body[:24] not in out and more[:24] not in out
    # The line is over the 8 KiB cap, so the stream masks the benign run the whole
    # text keeps (the documented fail-closed exception); from the END line on, both
    # agree.
    end = out[out.rindex("-----END") :]
    whole = redact(text)[0]
    assert end == whole[whole.rindex("-----END") :]
    assert body[:24] not in whole


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_pair_after_the_key_on_the_cookie_line_stays_masked(entry: str) -> None:
    # The drop is carried to the LATER of the line end and the key's end, so a key
    # pair on the same line after the key's END is still dropped with the line.
    from redaction_structured_cases import PEM_BEGIN, aws_key_id, aws_secret

    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    end = PEM_BEGIN.replace("BEGIN", "END")
    body = synth(200, B64, 67)
    secret = aws_secret()
    session = synth(48, B64, 69)
    text = (
        f"Cookie: session={'a' * 13000}{PEM_BEGIN}{body}{end} {aws_key_id()} {secret}"
        f"; session={session}\nafter"
    )
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = _feed_in(s, text, 1024)
    # The session pair after the key has no Cookie name left in the look-behind, so
    # only the line drop masks it.
    assert secret not in out and body[:24] not in out and session not in out
    assert out.endswith("\nafter")


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_key_ending_after_the_cookie_line_is_dropped_to_its_end_only(entry: str) -> None:
    # The drop runs through the key's END and no further: the line after it streams.
    from redaction_structured_cases import PEM_BEGIN

    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    end = PEM_BEGIN.replace("BEGIN", "END")
    body = [synth(64, B64, 71 + k) for k in range(2)]
    text = f"Cookie: session={'a' * 13000}{PEM_BEGIN}\n{body[0]}\n{body[1]}\n{end}\nkept line\n"
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = _feed_in(s, text, 1024)
    assert body[0][:24] not in out and body[1][:24] not in out
    assert out.endswith(f"{end}\nkept line\n")


@pytest.mark.parametrize("chunk", [7, 1024])
@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_long_key_opened_during_the_drop_ends_it_at_its_end_line(entry: str, chunk: int) -> None:
    # A real-size key body (3,000 characters) moves its BEGIN out of the look-behind
    # before its END arrives; the drop still stops at that END line, read from the
    # header, and the line after it streams.
    from redaction_structured_cases import PEM_BEGIN

    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    end = PEM_BEGIN.replace("BEGIN", "END")
    lines = [synth(64, B64, 90 + k) for k in range(47)]
    text = f"Cookie: session={'a' * 13000}{PEM_BEGIN}\n" + "\n".join(lines)
    text += f"\n{end}\nAFTERLINE visible\n"
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = _feed_in(s, text, chunk)
    assert not any(line[:24] in out for line in lines)
    assert out.endswith(f"{end}\nAFTERLINE visible\n")


@pytest.mark.parametrize("chunk", [7, 48, 1024])
@pytest.mark.parametrize("entry", ["structured", "production"])
def test_an_end_line_before_the_begin_does_not_close_the_drop(entry: str, chunk: int) -> None:
    # A stray END line on the Cookie line ahead of the BEGIN does not end the block.
    from redaction_structured_cases import PEM_BEGIN

    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    end = PEM_BEGIN.replace("BEGIN", "END")
    lines = [synth(64, B64, 140 + k) for k in range(47)]
    text = f"Cookie: session={'a' * 13000}{end}{'x' * 30}{PEM_BEGIN}\n" + "\n".join(lines)
    text += f"\n{end}\nAFTERLINE visible\n"
    s = StreamRedactor() if entry == "structured" else ProductionStreamRedactor()
    out = _feed_in(s, text, chunk)
    assert not any(line[:24] in out for line in lines)


def _hit_anchored_below(base: int) -> object:
    from kiro_crew.security.redaction_structured.model import SECRET, Hit

    return Hit(base + 5, base + 100, "http.session_cookie", SECRET, "cookie", "known_key", anchor=0)


def _anchored_below_scenario(case: str, ctx: str, buf: str) -> object:
    # Runs in the child: the patch the scenario needs is applied there, from plain
    # data, so the child can be spawned on every platform.
    from kiro_crew.security.redaction_structured import compat, stream
    from kiro_crew.security.redaction_structured.engine import ScanResult

    hit = _hit_anchored_below(len(ctx))
    if case == "compat":
        compat._read = lambda text, final=True: compat._Read(  # noqa: SLF001
            ctx + text, [hit], [hit], None, len(ctx), None
        )
        read = compat.stream_read(ctx, buf, boundary=False)
        return (read.cut, bool(read.undecided))
    stream.scan = lambda w, final, origin, **_: ScanResult([hit], None)
    stream.resolve = lambda hits: hits
    s = StreamRedactor()
    s._ctx = ctx  # noqa: SLF001
    return s.feed(buf)


def _split_feeds_scenario(first: str, second: str) -> object:
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    s = ProductionStreamRedactor()
    return s.feed(first) + s.feed(second) + s.flush()


def _serve(requests: object, replies: object, log: str) -> None:
    # The module's one worker child: it runs each scenario request in turn and puts an
    # ``("ok", value)`` or ``("error", text)`` record back. The attributes a scenario
    # patches are put back after each request, so one request's patch never reaches the
    # next. Its stderr goes to *log*, so a parent that finds it dead can quote the tail.
    import os
    import sys
    import traceback

    from kiro_crew.security.redaction_structured import compat, stream

    err = open(log, "a", buffering=1)  # noqa: SIM115 - held for the child's lifetime
    os.dup2(err.fileno(), 2)
    sys.stderr = err
    patched = [(compat, "_read"), (stream, "scan"), (stream, "resolve")]
    while True:
        request = requests.get()  # type: ignore[attr-defined]
        if request is None:
            return
        target, args = request
        saved = [getattr(mod, name) for mod, name in patched]
        try:
            replies.put(("ok", target(*args)))  # type: ignore[attr-defined]
        except BaseException as exc:  # noqa: BLE001 - reported to the test, not swallowed
            tail = "".join(traceback.format_exception(exc)[-6:])
            replies.put(("error", f"{type(exc).__name__}: {exc}\n{tail}"))  # type: ignore[attr-defined]
        finally:
            for (mod, name), value in zip(patched, saved):
                setattr(mod, name, value)


class _Worker:
    def __init__(self, log: str) -> None:
        import multiprocessing

        ctx = multiprocessing.get_context("spawn")
        self.log = log
        self.requests, self.replies = ctx.Queue(), ctx.Queue()
        self.child = ctx.Process(
            target=_serve, args=(self.requests, self.replies, log), daemon=True
        )
        self.child.start()

    def _state(self) -> str:
        code = self.child.exitcode
        return "alive" if code is None else f"exit code {code}"

    def _stderr_tail(self) -> str:
        try:
            with open(self.log, encoding="utf-8", errors="replace") as fh:
                return "".join(fh.readlines()[-10:])
        except OSError as exc:
            return f"(no stderr log: {exc})"

    def run(self, target: Callable[..., object], *args: object) -> object:
        import queue
        import time

        from kiro_crew.testing.wait import default_timeout

        # A module-level target and plain-data arguments, so the spawned child takes
        # them on every platform. The module fixture owns the one child: a dead child
        # fails the test at once, and no replacement starts mid-module.
        name = f"{target.__name__}{args!r}"
        if not self.child.is_alive():
            pytest.fail(
                f"scenario worker is dead before {name} ({self._state()});"
                f" last stderr:\n{self._stderr_tail()}"
            )
        deadline = default_timeout()
        started = time.monotonic()
        self.requests.put((target, args))
        try:
            kind, value = self.replies.get(timeout=default_timeout())
        except queue.Empty:
            elapsed = time.monotonic() - started
            state = self._state()
            self.child.kill()
            self.child.join(deadline)
            pytest.fail(
                f"{name} did not return in {elapsed:.1f}s (deadline {deadline:.1f}s,"
                f" child {state}); last stderr:\n{self._stderr_tail()}"
            )
        if kind == "error":
            pytest.fail(f"{name} raised in the scenario worker: {value}")
        return value

    def close(self) -> None:
        from kiro_crew.testing.wait import default_timeout

        if self.child.is_alive():
            self.requests.put(None)
            self.child.join(default_timeout())
        if self.child.is_alive():
            self.child.kill()
            self.child.join(default_timeout())
        assert not self.child.is_alive(), "the scenario worker did not stop"


@pytest.fixture(scope="module")
def scenario_worker(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Worker]:
    # One interpreter child for the module, not one per test.
    worker = _Worker(str(tmp_path_factory.mktemp("scenario_worker") / "stderr.log"))
    try:
        yield worker
    finally:
        worker.close()


_SCENARIO_GROUP = pytest.mark.xdist_group(name="redaction_stream_scenario_worker")


@_SCENARIO_GROUP
def test_the_cut_retreat_ends_for_a_hit_anchored_in_emitted_text(
    scenario_worker: _Worker,
) -> None:
    # A hit decided from text already emitted (anchor below the window's base)
    # cannot pull the cut back past the base: the retreat stops and holds.
    ctx, buf = "Cookie: theme=" + "a" * 30, "x" * 5 + "V" * 95 + "y" * 20
    assert scenario_worker.run(_anchored_below_scenario, "compat", ctx, buf) == (0, True)


@_SCENARIO_GROUP
def test_the_structured_stream_cut_retreat_ends_for_a_hit_anchored_in_committed_text(
    scenario_worker: _Worker,
) -> None:
    ctx, buf = "Cookie: theme=" + "a" * 30, "x" * 5 + "V" * 95 + "y" * 20
    assert scenario_worker.run(_anchored_below_scenario, "stream", ctx, buf) == ""


@_SCENARIO_GROUP
def test_a_cookie_name_split_from_its_value_across_feeds_returns(
    scenario_worker: _Worker,
) -> None:
    value = synth(48, B64, 29)
    tail = f'": theme={PEM_BEGIN}; session={value}";\nafter'
    for first, second in (("Cookie ", tail), ('"Cookie', " " + tail)):
        assert value not in str(scenario_worker.run(_split_feeds_scenario, first, second))


def test_a_cookie_name_with_no_separator_streams_in_linear_work() -> None:
    # Each ``cookie`` anchor with no separator after it is decided from a bounded
    # run of blanks, so the package's work per input byte stays flat: within 2.2x
    # across 8 KiB, 64 KiB and 512 KiB, counted in executed lines, never timed.
    from redaction_structured_cases import package_lines

    def per_byte(size: int) -> float:
        text = ("cookie x " * (size // 9 + 1))[:size]

        def run() -> None:
            s = StreamRedactor()
            s.feed(text)
            s.flush()

        return package_lines(run) / size

    rates = [per_byte(size) for size in (8 << 10, 64 << 10, 512 << 10)]
    assert max(rates) <= min(rates) * 2.2, rates


def test_repeated_cookie_anchors_before_an_invisible_name_stream_in_linear_work() -> None:
    # Every ``Cookie:`` anchor's name runs to the same far ``=`` and holds an ignorable
    # character, so each anchor reads the folded name: the line is folded once, so the
    # package's work per input byte stays flat, counted in executed lines, never timed.
    from redaction_structured_cases import package_lines

    def per_byte(count: int) -> float:
        text = "Cookie: " * count + "ses\u200bsion=" + _SET_COOKIE_TOKEN + ";\n"
        out: list[str] = []

        def run() -> None:
            s = StreamRedactor()
            out.extend((s.feed(text), s.flush()))

        rate = package_lines(run) / len(text)
        assert _SET_COOKIE_TOKEN not in "".join(out), count
        return rate

    rates = [per_byte(count) for count in (500, 1000, 2000)]
    assert max(rates) <= min(rates) * 2.2, rates


# ── Linear work on adversarial input ──


def _adversarial() -> list[tuple[str, Callable[[int], str]]]:
    def fill(unit: str, lead: str = "") -> Callable[[int], str]:
        return lambda n: lead + (unit * (n // len(unit) + 1))[:n]

    return [
        ("ghp_near_miss", fill("ghp_" + "a" * 35 + " ")),
        ("ghp_glued", fill("ghp_")),
        ("eyj_dots", fill("eyJ.")),
        ("eyj_link_shape", fill("eyJ" + "A" * 96 + ".")),
        ("begin_headers", fill("-----" + "BEGIN ")),
        ("begin_typed", fill(PEM_BEGIN + " ")),
        ("key_ids_beside_secrets", fill(f"{aws_key_id()} {aws_secret()} ")),
        ("akia_eq", fill("AKIA=")),
        ("known_key_repeat", fill("aws_secret_access_key=")),
        ("known_key_json", fill('"SecretAccessKey": "')),
        ("arn_repeat", fill("arn:")),
        ("url_repeat", fill("https://")),
        ("url_nested_query", fill("a://h/?state=")),
        ("anthropic_near", fill("sk-ant-api0")),
        ("b64_run", fill("A")),
        ("session_run", fill("A", lead="SessionToken=")),
        ("mask_run_lower", fill("x")),
        ("mask_run_upper", fill("X")),
        ("star_run", fill("*")),
        ("plain", fill("lorem ipsum dolor ")),
        ("deep_quotes", fill('"\\"')),
        ("cookie_pairs", fill("cookie=AAAAAAAA; ")),
        ("cookie_header_pairs", fill("a=AAAAAAAA; cookie=B; ", lead="Cookie: ")),
        ("cookie_colon", fill("cookie: ")),
        ("cookie_line", fill("a=1; ", lead="Cookie: ")),
        ("cookie_no_sep", fill("cookie x ")),
    ]


def _streamed(text: str) -> None:
    s = StreamRedactor()
    for i in range(0, len(text), 4096):
        s.feed(text[i : i + 4096])
    s.flush()


@pytest.mark.parametrize("build", [pytest.param(b, id=n) for n, b in _adversarial()])
def test_adversarial_input_costs_linear_work_whole(build: Callable[[int], str]) -> None:
    assert_linear_work(build, redact)


@pytest.mark.parametrize("build", [pytest.param(b, id=n) for n, b in _adversarial()])
def test_adversarial_input_costs_linear_work_streamed(build: Callable[[int], str]) -> None:
    assert_linear_work(build, _streamed)


@pytest.mark.parametrize("window", [' password="Zq8v', ' password="Zq8v Lm', ' password="Zq8v密'])
def test_an_open_unit_that_started_before_the_origin_still_holds(window: str) -> None:
    """The label sits in the look-behind (before ``origin``) and its value is
    still open, so the scan reports it open from ``origin`` instead of dropping it."""
    from kiro_crew.security.redaction_structured.engine import scan

    assert scan(window, final=False, origin=1).open_from == 1


def _glued_armour_headers() -> str:
    """A PGP block whose END line starts inside its BEGIN header runs to
    the next glued pair, past the look-behind; whole text then reads the EC header
    after it as unterminated and masks the tail."""
    pgp = PGP_BEGIN + PGP_END[5:]
    ec_begin = "-----BEGIN EC " "PRIVATE KEY-----"
    rows = "\\n".join(f"M{k:05d}Q" + synth(56, B64, 800 + k) for k in range(40))
    return (
        f"Cookie: theme={'a' * 9100}{pgp}\\n{rows}\\n{pgp}{ec_begin}"
        f"-----END {'X' * 58} "
        "PRIVATE KEY-----" + PEM_BEGIN_PLAIN + "\nTAIL M32702Z visible\n"
    )


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 7, 64])
def test_a_long_cookie_value_keeps_a_key_id_in_the_look_behind(entry: str, chunk: int) -> None:
    # The look-behind keeps its raw tail behind the kept Cookie name, so a key id a
    # few pairs before its secret still pairs with it, as in the whole text.
    from kiro_crew.testing.synthetic_credentials import aws_secret

    secret = aws_secret()
    key_id = "AKIA" + "QWERTYUIOPASDFGH"  # split so no key-id literal sits in the repo
    text = f"Cookie: z={'q' * 1100}; a={key_id}; {'b=1; ' * 10}c={secret}\nafter"
    assert secret not in redact(text)[0]
    s, _ = _redactor(entry)
    assert secret not in _feed_in(s, text, chunk)


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 7, 64, 1024])
def test_a_session_pair_before_a_held_pair_commits_masked(entry: str, chunk: int) -> None:
    # The hold covers only the line's last pair; the pairs before it keep their hits.
    value = synth(40, B64, 43)
    text = f"Cookie: sessionid={value}; theme={'a' * 2000}\nafter"
    assert value not in redact(text)[0]
    s, _ = _redactor(entry)
    assert value not in _feed_in(s, text, chunk)


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 7, 64, 1024])
def test_a_look_behind_starting_inside_a_value_reads_no_cookie_name(entry: str, chunk: int) -> None:
    # The kept tail starts inside ``x``'s value; read as a cookie name, its ``csrf``
    # would make ``session`` a forgery-cookie pair and release it.
    value = synth(40, B64, 47)
    text = f"Cookie: x={'q' * 1001}csrfdef; session={value}\nafter"
    assert value not in redact(text)[0]
    s, _ = _redactor(entry)
    assert value not in _feed_in(s, text, chunk)


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_a_line_cap_decided_from_a_kept_name_drops_from_the_origin(entry: str) -> None:
    value = synth(40, B64, 53)
    first, rest = "Cookie: a=1; ", f"{'b=2; ' * 1700}session={value}; c=3\nafter"
    assert value not in redact(first + rest)[0]
    s, _ = _redactor(entry)
    out = s.feed(first) + s.feed(rest) + s.flush()  # type: ignore[attr-defined]
    assert value not in out
    assert out.endswith("\nafter")


_SESSION_FIRST = ["session", "auth_token", "sid", "JSESSIONID"]
_TOKEN_SECOND = ["access_token", "token", "refresh_token", "auth_token"]


def _quoted_pairs_text(q: str) -> tuple[str, list[str]]:
    vals = [synth(24, B64, 80 + k) for k in range(5)]
    text = (
        f'a"b Cookie : session={q}{vals[0]}{q};k46=v0;theme={"a" * 300};k83=v1;'
        f"JSESSIONID={vals[1]};auth_token={q}{vals[2]}{q};auth_token={q}{vals[3]}{q};"
        f"access_token={vals[4]}{synth(16, B64, 90)};theme={'a' * 300}\nafter"
    )
    return text, vals[:4]


@pytest.mark.parametrize("chunk", [1, 4, 9])
@pytest.mark.parametrize("q", ['"', "'"])
def test_a_floor_raise_never_ends_before_a_closing_quote(q: str, chunk: int) -> None:
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    text, vals = _quoted_pairs_text(q)
    whole = redact(text)[0]
    assert not any(v in whole for v in vals[1:])
    assert _feed_in(ProductionStreamRedactor(), text, chunk) == whole


@pytest.mark.parametrize("q", ['"', "'"])
def test_the_decided_cut_takes_the_closing_quote_with_its_value(q: str) -> None:
    from kiro_crew.security.text_redaction import _decided_cut

    buf = f"x auth_token={q}{synth(24, B64, 99)}{q};a=1"
    before_quote = buf.index(q, buf.index("=")) + 25
    assert buf[before_quote] == q
    assert _decided_cut(buf, before_quote) == before_quote + 1
    assert _decided_cut(buf, len(buf)) == len(buf)


def _decided_pair_text(first: str, second: str, size: int = 600) -> tuple[str, str]:
    value = synth(40, B64, 61)
    return f"Cookie: {first}={value}; {second}={synth(size, B64, 67)}\nafter", value


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", range(1, 9))
def test_a_decided_session_pair_is_never_split_by_the_floor(entry: str, chunk: int) -> None:
    # The production floor (512 behind a token anchor) once sat below the detectors'
    # cut and committed four characters at a time through the decided session value.
    text, value = _decided_pair_text("session", "access_token")
    s, _ = _redactor(entry)
    out = _feed_in(s, text, chunk)
    assert value not in out
    assert out == redact(text)[0]


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("size", [470, 600])
@pytest.mark.parametrize("second", _TOKEN_SECOND)
@pytest.mark.parametrize("first", _SESSION_FIRST)
def test_a_decided_session_pair_before_a_long_token_commits_masked(
    entry: str, first: str, second: str, size: int
) -> None:
    text, value = _decided_pair_text(first, second, size)
    s, _ = _redactor(entry)
    out = _feed_in(s, text, 4)
    assert value not in out
    assert out == redact(text)[0]


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize(
    "first,size", [(0, 1), (0, 7), (0, 256), (0, 1024), (8200, 48), (8156, 1024), (8171, 4097)]
)
def test_a_block_past_the_look_behind_keeps_the_scan_where_whole_text_resumes_it(
    entry: str, first: int, size: int
) -> None:
    import kiro_crew.security as production

    text = _glued_armour_headers()
    whole = redact(text)[0]
    assert "M32702Z" not in whole
    s = StreamRedactor() if entry == "structured" else production.StreamRedactor()
    out = s.feed(text[:first]) if first else ""
    out += "".join(s.feed(text[i : i + size]) for i in range(first, len(text), size)) + s.flush()
    assert "M32702Z" not in out
    if entry == "structured":
        assert out == whole


def test_a_completed_block_split_by_the_floor_keeps_its_retained_body_masked() -> None:
    import kiro_crew.security as production
    from kiro_crew.security.redaction_switch import always_scan

    ec_begin = "-----BEGIN EC " "PRIVATE KEY-----"
    text = (
        f"prefix {PEM_BEGIN}\nSYNTHETIC_ALPHA "
        + "q " * 2100
        + f"{ec_begin}\nSYNTHETIC_OMEGA\n{PEM_END}\n"
        + f"{PEM_BEGIN}\n{synth(64, B64, 41)}\n{PEM_END}\n"
    )
    with always_scan():
        whole = production.redact(text)
        stream = production.StreamRedactor()
        out = "".join(stream.feed(text[i : i + 64]) for i in range(0, len(text), 64))
        out += stream.flush()
    assert "SYNTHETIC_ALPHA" not in out
    assert "SYNTHETIC_OMEGA" not in out
    assert out == whole


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize(
    "body", ["Cookie: x=1; ", "a=1; Cookie: b=2; ", "c=1; cookie=2; ", "k1=v;cookie=v;"]
)
def test_a_second_cookie_name_on_a_running_line_adds_no_earlier_hold(
    entry: str, body: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An inner name's walk that meets a held pair holds where that walk held, so
    # each scan still reads only the look-behind and new text.
    from kiro_crew.security.redaction_structured import engine, stream

    scanned: list[int] = []
    real = engine.scan

    def counting(text: str, *args: object, **kwargs: object) -> object:
        scanned.append(len(text))
        return real(text, *args, **kwargs)  # type: ignore[arg-type]

    line = ("Cookie: " + body * (8000 // len(body)))[:8000]
    whole = redact(line + "\nafter")[0]
    monkeypatch.setattr(engine, "scan", counting)
    monkeypatch.setattr(stream, "scan", counting)
    s, _ = _redactor(entry)
    out = _feed_in(s, line + "\nafter", 4)
    assert max(scanned) <= 2 * stream.CONTEXT
    assert out == whole


def _label_cut_text(head: str, off: int, seed: int) -> tuple[str, str]:
    """``head`` then a blank run sized so the stream's CONTEXT look-behind cut lands
    ``off`` characters into ``head``, then a newline and a secret."""
    secret = synth(40, B64, seed)
    return head + " " * (CONTEXT - len(head) + off) + "\n" + secret + "\nafter", secret


@pytest.mark.parametrize("chunk", [1, 48, 512])
@pytest.mark.parametrize(
    ("head", "off", "entry"),
    [
        # The cuts where 53c1706469's ``_`` stand-in diverged and base did not.
        ("Proxy-Authorization: Bearer", 5, "production"),
        ("Proxy-Authorization: Bearer", 6, "structured"),
        ("X-Authorization: Bearer", 1, "production"),
        ("X-Authorization: Bearer", 2, "structured"),
    ],
)
def test_a_cut_after_a_header_hyphen_keeps_the_scheme_header_reading(
    entry: str, chunk: int, head: str, off: int
) -> None:
    # A cut right after the ``-`` of a prefixed Authorization name: the look-behind
    # keeps the whole name run, so it reads as the whole text reads it.
    text, secret = _label_cut_text(head, off, 101 + off)
    whole = redact(text)[0]
    assert secret not in whole
    s, _ = _redactor(entry)
    assert _feed_in(s, text, chunk) == whole


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 48, 512])
@pytest.mark.parametrize(("name", "off"), [("X-Api-Key", 2), ("x-goog-api-key", 7)])
def test_a_cut_inside_a_hyphenated_key_header_keeps_the_whole_name(
    entry: str, chunk: int, name: str, off: int
) -> None:
    # The cut lands right after ``X-`` or ``x-goog-``: no stand-in character reads as the
    # whole name there, so the look-behind keeps the run from its start.
    head = name + ": "
    key = synth(40, B64, 77)
    text = head + " " * (CONTEXT - len(head) + off) + key + "\nafter"
    whole = redact(text)[0]
    assert key not in whole
    s, _ = _redactor(entry)
    assert _feed_in(s, text, chunk) == whole


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 4, 7, 9])
def test_a_suffix_of_an_over_long_header_name_reads_as_the_whole_text(
    entry: str, chunk: int
) -> None:
    # ``VeryLongCustomPrefix-Api-Key`` is no table name: its ``Api-Key`` suffix,
    # left at the look-behind's head by a cut, must not anchor the key reader.
    value = synth(48, B64, 123)
    text = "VeryLongCustomPrefix-Api-Key:" + " " * 1017 + value + "\nafter"
    whole = redact(text)[0]
    assert value in whole
    s, _ = _redactor(entry)
    assert _feed_in(s, text, chunk) == whole


def test_a_cut_inside_a_table_name_retreats_and_takes_no_stand_in() -> None:
    from kiro_crew.security.redaction_structured.headers import (
        _header_name_max,
        _tail_from,
    )

    for name in ("x-goog-api-key", "Proxy-Authorization"[:14], "Set-Cookie"):
        assert len(name) <= _header_name_max()
        text = "a " + name + ": v"
        for cut in range(3, 2 + len(name)):
            assert _tail_from(text, cut) == text[2:]


def test_a_cut_inside_an_over_long_run_keeps_the_cut_behind_a_stand_in() -> None:
    from kiro_crew.security.redaction_structured.headers import (
        _header_name_max,
        _tail_from,
    )

    text = "a " + "VeryLongCustomPrefix-Api-Key" + ": v"
    cut = text.index("Api-Key")
    assert cut - 2 > _header_name_max()
    assert _tail_from(text, cut) == "-" + text[cut:]
    assert _tail_from(text, cut + 1) == "_" + text[cut + 1 :]


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_the_proxy_authorization_trigger_reads_as_the_whole_text(entry: str) -> None:
    token = synth(40, B64, 77)
    text = "Proxy-Authorization: Bearer" + " " * 1002 + "\n" + token + "\nafter"
    whole = redact(text)[0]
    assert token not in whole
    s, _ = _redactor(entry)
    assert _feed_in(s, text, 48) == whole
    s, _ = _redactor(entry)
    split = s.feed(text[:1040]) + s.feed(text[1040:]) + s.flush()  # type: ignore[attr-defined]
    assert split == whole


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("value", ["Bearer", "session="])
@pytest.mark.parametrize("name", ["Cookie", "Set-Cookie", "X-Cookie"])
def test_a_cookie_family_label_cut_anywhere_reads_as_the_whole_text(
    entry: str, value: str, name: str
) -> None:
    head = f"{name}: {value}"
    for off in range(-2, len(head) + 2):
        text, _ = _label_cut_text(head, off, 131 + off)
        s, _ = _redactor(entry)
        assert _feed_in(s, text, 48) == redact(text)[0], off


def _prefixed_cookie_text(name: str) -> tuple[str, str]:
    ext = synth(48, B64, 59)
    return f"{name}: ordinary=one; Path=/{'p' * 1600}; session={ext}\nafter", ext


@pytest.mark.parametrize("name", ["Set-Cookie", "MyCookie", "X-Cookie"])
def test_a_look_behind_cut_inside_a_prefixed_name_reads_no_cookie_anchor(name: str) -> None:
    # A cut that lands inside ``Set-Cookie`` (or ``MyCookie``) must not leave a fresh
    # ``Cookie:`` at the head of the look-behind: the stream reads as the whole text.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    text, _ = _prefixed_cookie_text(name)
    whole = redact(text)[0]
    production = ProductionStreamRedactor()
    split = production.feed(text[:1540]) + production.feed(text[1540:]) + production.flush()
    assert split == whole
    structured = StreamRedactor()
    assert _feed_in(structured, text, 1) == whole
    assert not any(sp[2] == "http.session_cookie" for sp in structured.spans)


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 512])
def test_a_kept_cookie_name_leaves_the_raw_look_behind_whole(entry: str, chunk: int) -> None:
    # The Cookie prefix rides in front of a full CONTEXT raw tail, so an
    # ``Authorization: Bearer`` label CONTEXT characters back still reads its token.
    token = synth(40, B64, 71)
    text = f"Cookie: session={'a' * 13000} Authorization: Bearer{' ' * 995}\n{token}\nafter"
    assert token not in redact(text)[0]
    s, _ = _redactor(entry)
    assert token not in _feed_in(s, text, chunk)


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 7, 128, 1024])
def test_a_long_benign_value_flows_and_a_later_session_pair_is_still_read(
    entry: str, chunk: int
) -> None:
    # ``theme`` is no masked name, so its 9,100 characters are not held; the name
    # stays in the look-behind, so the ``session`` pair after it is still read.
    value = synth(40, B64, 137)
    text = f"Cookie: theme={'a' * 9100}; session={value}\nafter"
    whole = redact(text)[0]
    assert "a" * 9100 in whole and value not in whole
    s, _ = _redactor(entry)
    assert _feed_in(s, text, chunk) == whole


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 512, 4097])
def test_a_session_value_past_the_bound_is_masked_to_the_line_end(entry: str, chunk: int) -> None:
    text = f"Cookie: session={synth(13000, B64, 139)}\nafter"
    whole = redact(text)[0]
    s, _ = _redactor(entry)
    assert _feed_in(s, text, chunk) == whole == f"Cookie: session={TAG}\nafter"


def _long_name_session_lines() -> list[tuple[str, str]]:
    value = synth(30, B64, 151)
    tail = f"session={value}; c=1\nafter\n"
    return [
        ("x" * 1100, "Cookie: theme=dark; " + "x" * 1100 + tail),
        ("dotted", "Cookie: theme=dark; " + ".".join(f"seg{k}" for k in range(220)) + "." + tail),
        ("dashed", "Cookie: theme=dark; " + "-".join(f"seg{k}" for k in range(220)) + "-" + tail),
    ]


@pytest.mark.parametrize(("shape", "chunk"), [(0, 1), (0, 3), (1, 1), (2, 1)])
def test_a_session_pair_with_a_long_name_keeps_its_name_with_the_cut(
    shape: int, chunk: int
) -> None:
    # The session hit is anchored at its pair start, so a commit never lands inside
    # its name and the look-behind never reads the name's tail as a value.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    _, text = _long_name_session_lines()[shape]
    whole = redact(text)[0]
    assert "session=" + TAG in whole
    assert _feed_in(ProductionStreamRedactor(), text, chunk) == whole


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_an_anchored_session_hold_stays_within_its_bound(entry: str) -> None:
    # The anchor keeps the pair whole, but the hold is still cut at COOKIE_LINE_HOLD.
    from kiro_crew.security.redaction_structured.headers import COOKIE_LINE_HOLD

    text = "Cookie: theme=dark; session=" + synth(13000, B64, 157) + "\nafter"
    s, pending = _redactor(entry)
    longest = 0
    for i in range(0, len(text), 64):
        s.feed(text[i : i + 64])  # type: ignore[attr-defined]
        longest = max(longest, len(getattr(s, pending)))
    s.flush()  # type: ignore[attr-defined]
    assert longest <= COOKIE_LINE_HOLD + 64


def test_a_name_far_from_its_colon_fails_closed_and_releases_no_session_value() -> None:
    # The kept tail starts at the first pair. More than 64 blanks before the colon
    # trips the separator rule (fail closed), so the stream masks the rest of the line,
    # more than the whole text does, and never the token.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    value = synth(40, B64, 161)
    head = "Cookie" + " " * 1017 + ": session="
    text = head + value + "\nafter"
    for chunk in (1, 3):
        out = _feed_in(ProductionStreamRedactor(), text, chunk)
        assert value not in out
        assert out == f"Cookie{TAG}\nafter"
    s = ProductionStreamRedactor()
    assert value not in s.feed(head) + s.feed(value + "\nafter") + s.flush()


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 3])
@pytest.mark.parametrize("gap", [1010, 1017, 1024])
def test_a_kept_tail_starting_at_the_first_pair_reads_that_pair(
    entry: str, chunk: int, gap: int
) -> None:
    # Blanks after the colon move the first pair to the look-behind's cut with no
    # separator rule involved: the tail follows the bare name and separator, so the
    # session pair is read as the whole text reads it.
    value = synth(40, B64, 173)
    text = "Cookie:" + " " * gap + "session=" + value + "\nafter"
    s, _ = _redactor(entry)
    assert _feed_in(s, text, chunk) == redact(text)[0]


def _first_pair_cut_cases() -> list[tuple[str, str]]:
    return [
        ("before", "Cookie" + " " * 1040 + ": session="),
        ("at", "Cookie" + " " * (CONTEXT - 2) + ": session="),
        ("one_in", "Cookie" + " " * (CONTEXT - 3) + ": session="),
        ("mid_pair", "Cookie: theme=" + "q" * 1200 + "; session="),
        ("at_separator", "Cookie: theme=" + "q" * (CONTEXT - 8) + "; session="),
    ]


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("back", [0, 3])
@pytest.mark.parametrize(("where", "head"), _first_pair_cut_cases())
def test_the_look_behind_cut_around_the_first_pair_reads_as_the_whole_text(
    entry: str, back: int, where: str, head: str
) -> None:
    # Everything before the session value is committed in one feed, so the cut lands
    # before, at, one past, inside or at a separator after the first pair's start.
    value = synth(40, B64, 171)
    text = head + value + "\nafter"
    s, _ = _redactor(entry)
    split = len(head) - back
    out = s.feed(text[:split]) + s.feed(text[split:]) + s.flush()  # type: ignore[attr-defined]
    assert out == redact(text)[0], where


_SET_COOKIE_TOKEN = "Zqr8eXogsl91eOcHdmweLBWS57JZIDk3Pq"


def _feeds(text: str, plan: object) -> list[str]:
    if isinstance(plan, int):
        return [text[i : i + plan] for i in range(0, len(text), plan)]
    cut = text.index(_SET_COOKIE_TOKEN)
    return [text[:cut], text[cut:]]


@pytest.mark.parametrize("plan", [1, 3, 16, 32, "value_after_name"])
@pytest.mark.parametrize(
    "head",
    [
        "Set-Cookie:" + " " * 1030 + "session=",
        "Set-Cookie:" + " " * 2000 + "session=",
        "Set-Cookie: session=",
    ],
)
def test_a_set_cookie_session_value_never_streams_once_its_name_is_cut(
    head: str, plan: object
) -> None:
    # The look-behind keeps a ``Set-Cookie`` name as it keeps ``Cookie``, so a session
    # value read after the name left the window is still read as that header's pair.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    text = head + _SET_COOKIE_TOKEN + "; c=1\nafter\n"
    assert _SET_COOKIE_TOKEN not in redact(text)[0]
    s = ProductionStreamRedactor()
    out = "".join(s.feed(c) for c in _feeds(text, plan)) + s.flush()
    assert _SET_COOKIE_TOKEN not in out


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("back", [0, 3])
@pytest.mark.parametrize(("where", "head"), _first_pair_cut_cases())
def test_a_set_cookie_cut_around_its_first_pair_reads_as_the_whole_text(
    entry: str, back: int, where: str, head: str
) -> None:
    head = "Set-" + head
    value = synth(40, B64, 179)
    text = head + value + "\nafter"
    s, _ = _redactor(entry)
    split = len(head) - back
    out = s.feed(text[:split]) + s.feed(text[split:]) + s.flush()  # type: ignore[attr-defined]
    assert out == redact(text)[0], where


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("plan", [1, 3, 16, 32, "value_after_name"])
def test_a_cookie_name_after_a_quoted_set_cookie_name_keeps_reading_every_pair(
    entry: str, plan: object
) -> None:
    # The reader reads this line's pairs from the plain ``cookie`` name after the
    # quoted ``Set-Cookie``; a kept window must carry that name, so ``auth`` after it
    # is still masked as the whole text masks it.
    value = synth(40, B64, 191)
    text = (
        '"Set-Cookie" : "cookie="'
        + "z" * 1500
        + '"; sessionid="1"; auth='
        + _SET_COOKIE_TOKEN
        + value
        + '"\nafter'
    )
    whole = redact(text)[0]
    assert _SET_COOKIE_TOKEN not in whole
    s, _ = _redactor(entry)
    out = "".join(s.feed(c) for c in _feeds(text, plan)) + s.flush()  # type: ignore[attr-defined]
    assert out == whole


@pytest.mark.parametrize("sep", [" ", ", ", '", "', " | ", "; "])
@pytest.mark.parametrize("gap", [1030, 2000])
def test_the_last_set_cookie_name_on_a_line_is_the_one_kept(sep: str, gap: int) -> None:
    # Two Set-Cookie names on one line: the later one's first pair is the one still
    # read, so the look-behind keeps that name.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    head = "Set-Cookie: a=1" + sep + "Set-Cookie:" + " " * gap + "session="
    text = head + _SET_COOKIE_TOKEN + "; Path=/\n"
    assert _SET_COOKIE_TOKEN not in redact(text)[0]
    s = ProductionStreamRedactor()
    out = s.feed(head) + s.feed(text[len(head) :]) + s.flush()
    assert _SET_COOKIE_TOKEN not in out


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 3, 64, 1024])
def test_a_kept_set_cookie_name_reads_only_its_first_pair(entry: str, chunk: int) -> None:
    # Set-Cookie reads only the pair after its name: a later ``other=`` value is left
    # as the whole text leaves it, so the kept name does not over-mask.
    text = (
        "Set-Cookie:"
        + " " * 1100
        + f"session={synth(40, B64, 181)}; other={synth(40, B64, 183)}\nafter"
    )
    s, _ = _redactor(entry)
    assert _feed_in(s, text, chunk) == redact(text)[0]


@pytest.mark.parametrize(
    ("head", "plan"),
    [
        # The splits where main masks this shape; at smaller feeds main leaks it too,
        # since the invisible-character pass reads each window without its look-behind.
        *(("Cookie: ses\u200bsion=", p) for p in (16, 32, 64, 128, "value_after_name")),
        *(("Cookie: theme=dark; ses\xadsion=", p) for p in (128, "value_after_name")),
    ],
)
def test_a_cookie_name_with_an_invisible_character_is_never_released(
    head: str, plan: object
) -> None:
    # Whole text folds the invisible character and reads a session name; the stream
    # holds such a pair from the header name, so the window that folds it still reads
    # ``Cookie:``.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor
    from kiro_crew.security import redact as production_redact

    text = head + _SET_COOKIE_TOKEN + "; c=1\nafter\n"
    whole = production_redact(text)
    assert _SET_COOKIE_TOKEN not in whole
    s = ProductionStreamRedactor()
    out = "".join(s.feed(c) for c in _feeds(text, plan)) + s.flush()
    assert out == whole


@pytest.mark.parametrize("chunk", [64, 1000])
@pytest.mark.parametrize("gap", [64, 1010, 1024, 1500, 2000])
def test_a_folded_session_name_after_a_far_benign_value_is_masked(gap: int, chunk: int) -> None:
    # The pair is complete in a window whose ``Cookie:`` is only in the look-behind:
    # the cookie reader judges the name with ignorable characters removed, as the
    # whole text does, so it masks the value there.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor
    from kiro_crew.security import redact as production_redact

    text = "Cookie: theme=" + "q" * gap + "; ses\u200bsion=" + _SET_COOKIE_TOKEN + "; c=1\nafter\n"
    whole = production_redact(text)
    assert _SET_COOKIE_TOKEN not in whole
    assert _feed_in(ProductionStreamRedactor(), text, chunk) == whole


@pytest.mark.parametrize("name", ["ses\u200bsion", "ses\xadsion"])
def test_the_cookie_reader_reads_a_session_name_through_ignorable_characters(name: str) -> None:
    from kiro_crew.security.redaction_structured.engine import scan

    text = f"Cookie: {name}={_SET_COOKIE_TOKEN}; c=1\n"
    hits = [h for h in scan(text).hits if h.rule_id == "http.session_cookie"]
    assert [text[h.start : h.end] for h in hits] == [_SET_COOKIE_TOKEN]
    assert hits[0].anchor == text.index(name)


@pytest.mark.parametrize("gap", [1030, 1100, 2000])
@pytest.mark.parametrize(
    "lead", ["Cookie: a=1;", "Cookie: theme=dark;", "Set-Cookie: a=1; Cookie: b=2;"]
)
def test_a_cut_in_the_blanks_after_a_separator_reads_the_next_pair_as_a_name(
    lead: str, gap: int
) -> None:
    # The cut falls between pairs: the placeholder ends with the ``;`` it stands for,
    # so ``session`` after the blanks is read as a pair name, as the whole text does.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    head = lead + " " * gap + "session="
    text = head + _SET_COOKIE_TOKEN + "; c=1\n"
    assert _SET_COOKIE_TOKEN not in redact(text)[0]
    s = ProductionStreamRedactor()
    assert _SET_COOKIE_TOKEN not in s.feed(head) + s.feed(text[len(head) :]) + s.flush()


@pytest.mark.parametrize("gap", [2060, 5000])
@pytest.mark.parametrize("blank", [" ", "\u00a0 \t"])
@pytest.mark.parametrize("name", ["session", "x" * 1100 + "_session"])
def test_a_long_blank_run_after_a_separator_still_reads_the_next_pair(
    gap: int, blank: str, name: str
) -> None:
    # The back-scan reads to the name's separator, however many blanks sit there.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor

    head = "Cookie: a=1;" + (blank * gap)[:gap] + name + "="
    text = head + _SET_COOKIE_TOKEN + "; c=1\n"
    assert _SET_COOKIE_TOKEN not in redact(text)[0]
    s = ProductionStreamRedactor()
    assert _SET_COOKIE_TOKEN not in s.feed(head) + s.feed(text[len(head) :]) + s.flush()


def test_the_separator_back_scan_costs_linear_work() -> None:
    # The back-scan reads the blanks back to the pair's separator with no budget, so
    # it masks the value after any blank run, and the package's work per input byte
    # stays flat as the run grows: within 2.2x from 32 KiB to 256 KiB of blanks, with the
    # whole run let go before the value arrives, counted in executed lines, never timed.
    from redaction_structured_cases import package_lines

    def per_byte(size: int) -> float:
        head = "Cookie: a=1;" + " " * size + "session="
        text = head + _SET_COOKIE_TOKEN + "; c=1\n"
        out: list[str] = []

        def run() -> None:
            s = StreamRedactor()
            out.extend((s.feed(head), s.feed(text[len(head) :])))
            out.append(s.flush())

        rate = package_lines(run) / len(text)
        assert _SET_COOKIE_TOKEN not in "".join(out), size
        return rate

    rates = [per_byte(size) for size in (32 << 10, 256 << 10)]
    assert max(rates) <= min(rates) * 2.2, rates


def test_the_placeholder_names_where_the_cut_fell() -> None:
    from kiro_crew.security.redaction_structured.headers import cookie_look_behind

    between = "Cookie: a=1;" + " " * 1500
    assert cookie_look_behind(between, CONTEXT).startswith("Cookie:_=;")
    inside = "Cookie: a=" + "q" * 1500
    kept = cookie_look_behind(inside, CONTEXT)
    assert kept.startswith("Cookie:_=") and not kept.startswith("Cookie:_=;")


@pytest.mark.parametrize("over", [False, True])
@pytest.mark.parametrize("name", ["\u200b sid", "\u200bsid", " \u200bsid"])
def test_a_cookie_name_is_folded_then_stripped(name: str, over: bool) -> None:
    # The name as whole text reads it: ignorable characters removed, then blanks
    # stripped, on both the direct and the line-scan reading of a name.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor
    from kiro_crew.security import redact as production_redact
    from kiro_crew.security.redaction_structured.headers import _NAME_DIRECT_MAX

    pad = "x" * (_NAME_DIRECT_MAX + 4) + "_" if over else ""
    text = f"Cookie: theme={'q' * 1500}; {pad}{name}={_SET_COOKIE_TOKEN}; c=1\n"
    whole = production_redact(text)
    assert _feed_in(ProductionStreamRedactor(), text, 64) == whole


@pytest.mark.parametrize("chunk", [1, 7, 64])
@pytest.mark.parametrize("name", ["cs\u00adrf_session", "x\u00adsrf-token", "sessionc\u200bsrf"])
def test_the_folded_name_only_adds_to_the_raw_reading(name: str, chunk: int) -> None:
    # A raw session reading stays a hit when the folded name holds a forgery word:
    # the batch plan's "the ignorable view only adds" rule, inside the reader.
    from kiro_crew.security import StreamRedactor as ProductionStreamRedactor
    from kiro_crew.security import redact as production_redact

    text = f"Cookie: {name}={_SET_COOKIE_TOKEN}; c=1\n"
    whole = production_redact(text)
    assert _SET_COOKIE_TOKEN not in whole
    assert _feed_in(ProductionStreamRedactor(), text, chunk) == whole


@pytest.mark.parametrize("entry", ["structured", "production"])
def test_an_ignorable_name_that_folds_to_a_benign_name_is_released(entry: str) -> None:
    # ``the\u200bme`` folds to ``theme``: benign, released once complete, as whole text.
    from kiro_crew.security import redact as production_redact

    text = f"Cookie: the\u200bme={'dark' * 300}; c=1\nafter\n"
    s, _ = _redactor(entry)
    out = _feed_in(s, text, 64)
    assert out == text == production_redact(text)


def test_a_long_cookie_name_keeps_the_raw_reading_and_its_bound() -> None:
    # A name past _NAME_DIRECT_MAX is read raw from the shared line scan, unfolded.
    from kiro_crew.security.redaction_structured.engine import scan
    from kiro_crew.security.redaction_structured.headers import _NAME_DIRECT_MAX

    long_name = "x" * (_NAME_DIRECT_MAX + 10) + "\u200b"
    text = f"Cookie: {long_name}={_SET_COOKIE_TOKEN}; c=1\n"
    assert not [h for h in scan(text).hits if h.rule_id == "http.session_cookie"]


@pytest.mark.parametrize("entry", ["structured", "production"])
@pytest.mark.parametrize("chunk", [1, 3, 64])
def test_an_ordinary_benign_pair_still_streams_as_it_arrives(entry: str, chunk: int) -> None:
    # A plain benign value is released as it arrives; only an invisible-character
    # name is held from the header.
    text = "Cookie: theme=" + "dark" * 600 + "\nafter"
    s, pending = _redactor(entry)
    longest = 0
    for i in range(0, len(text), chunk):
        s.feed(text[i : i + chunk])  # type: ignore[attr-defined]
        longest = max(longest, len(getattr(s, pending)))
    s.flush()  # type: ignore[attr-defined]
    assert longest <= 512


def test_blanks_after_a_cookie_separator_keep_the_look_behind_bounded() -> None:
    from kiro_crew.security.redaction_structured.headers import cookie_look_behind

    kept = cookie_look_behind("Cookie:" + " " * 8191 + "a=1", CONTEXT)
    assert len(kept) <= CONTEXT + len("Cookie:")
    assert kept.startswith("Cookie:")

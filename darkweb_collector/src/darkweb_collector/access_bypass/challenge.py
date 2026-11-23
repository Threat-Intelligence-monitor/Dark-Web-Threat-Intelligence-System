"""Wait out, and if necessary answer, an anti-bot interstitial in a real browser.

A managed Cloudflare challenge usually clears itself once the page's own script
has run: the reason ``darkforums.as`` blocks curl is not that curl cannot run
JavaScript, it is that the *fingerprint* scored as a bot.  So the browser path
does not need a human: a stealth context plus patience is normally enough.

Some cases do need an interaction, and only an interaction:

* a Turnstile widget waiting for its checkbox,
* a "Verify you are human" button,
* a DDoS-Guard page that only finishes after real input events.

This module performs those interactions with a synthesised human pointer path
rather than ``element.click()``: the widget checks event ``isTrusted`` and the
pointer trajectory, and a zero-duration click at the exact centre of the box is
the classic signature of a solver.

It never types credentials and never solves an image captcha; those are
reported back as unresolved so the caller records ``blocked``/``auth_required``
instead of burning the budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import random
import time
from typing import Any, Callable, Mapping

from darkweb_collector.access_bypass.detect import classify_html
from darkweb_collector.access_bypass.model import BypassProfile, ProtectionSignal

#: Frame URL fragments that host the challenge widget itself.
CHALLENGE_FRAME_HINTS: tuple[str, ...] = (
    "challenges.cloudflare.com",
    "challenge-platform",
    "challenge-stage",
    "turnstile",
)

#: Selectors that mean "click me to pass", in order of specificity.
CHECKBOX_SELECTORS: tuple[str, ...] = (
    "input[type=checkbox]",
    "#challenge-stage input",
    "label.cb-lb input",
    "div.cb-c input",
    "button[type=submit]",
    "input[type=submit]",
)

#: Elements that are safe to click when no checkbox is exposed.
BUTTON_TEXT_HINTS: tuple[str, ...] = (
    "verify you are human", "i am human", "continue", "verify", "checking",
)


@dataclass
class SolveResult:
    solved: bool
    html: str
    signal: ProtectionSignal
    waited_ms: int = 0
    reason: str = ""
    notes: list[str] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)

    def describe(self) -> str:
        state = "solved" if self.solved else "unresolved"
        return f"{state} after {self.waited_ms}ms [{self.signal.describe()}]" + (
            f" {self.reason}" if self.reason else "")


def _now() -> float:
    return time.monotonic()


def _emit(on_event: Callable[[Mapping[str, Any]], None] | None, payload: Mapping[str, Any]) -> None:
    if on_event is None:
        return
    try:
        on_event(payload)
    except Exception:
        pass


def human_click(page: Any, box: Mapping[str, float], *, rng: random.Random | None = None) -> bool:
    """Click inside ``box`` (viewport pixels) along a curved pointer path."""

    rng = rng or random.Random()
    if not box:
        return False
    try:
        start_x, start_y = _pointer(page)
        target_x = float(box["x"]) + float(box["width"]) * rng.uniform(0.35, 0.65)
        target_y = float(box["y"]) + float(box["height"]) * rng.uniform(0.35, 0.65)
        steps = rng.randint(14, 26)
        control_x = (start_x + target_x) / 2 + rng.uniform(-60, 60)
        control_y = (start_y + target_y) / 2 + rng.uniform(-40, 40)
        for step in range(1, steps + 1):
            t = step / steps
            # Quadratic Bezier with a slight ease-out, like a hand.
            eased = 1 - (1 - t) ** 2
            x = (1 - eased) ** 2 * start_x + 2 * (1 - eased) * eased * control_x + eased ** 2 * target_x
            y = (1 - eased) ** 2 * start_y + 2 * (1 - eased) * eased * control_y + eased ** 2 * target_y
            page.mouse.move(x, y)
            page.wait_for_timeout(rng.randint(8, 22))
        page.wait_for_timeout(rng.randint(80, 220))
        page.mouse.down()
        page.wait_for_timeout(rng.randint(40, 110))
        page.mouse.up()
        return True
    except Exception:
        return False


def _pointer(page: Any) -> tuple[float, float]:
    try:
        value = page.evaluate("() => ({x: window.__dshX || 0, y: window.__dshY || 0, w: innerWidth, h: innerHeight})")
        if isinstance(value, Mapping):
            return float(value.get("x") or value.get("w", 640) / 2), float(value.get("y") or 40)
    except Exception:
        pass
    return 640.0, 40.0


def wander(page: Any, *, rng: random.Random | None = None) -> None:
    """A few idle pointer moves and a small scroll, as a waiting human makes."""

    rng = rng or random.Random()
    try:
        size = page.viewport_size or {"width": 1440, "height": 960}
        width = float(size.get("width") or 1440)
        height = float(size.get("height") or 960)
        for _ in range(rng.randint(1, 3)):
            page.mouse.move(rng.uniform(60, width - 120), rng.uniform(80, height / 2))
            page.wait_for_timeout(rng.randint(60, 180))
        if rng.random() < 0.5:
            page.mouse.wheel(0, rng.randint(80, 260))
            page.wait_for_timeout(rng.randint(120, 300))
    except Exception:
        pass


def _find_challenge_frame(page: Any) -> Any:
    try:
        frames = list(page.frames)
    except Exception:
        return None
    for frame in frames:
        url = (getattr(frame, "url", "") or "").lower()
        if any(hint in url for hint in CHALLENGE_FRAME_HINTS):
            return frame
    return None


def click_challenge(page: Any, *, rng: random.Random | None = None) -> tuple[bool, str]:
    """Try to click the challenge widget.  Returns ``(clicked, reason)``."""

    rng = rng or random.Random()
    frame = _find_challenge_frame(page)
    if frame is not None:
        for selector in CHECKBOX_SELECTORS:
            try:
                locator = frame.locator(selector).first
                if locator.count() == 0:
                    continue
                box = locator.bounding_box()
                if box and box.get("width") and box.get("height"):
                    if human_click(page, box, rng=rng):
                        return True, f"clicked {selector} in challenge frame"
                # The checkbox may report a zero-sized box while the widget is
                # still animating; clicking the widget centre usually works.
                frame_box = _frame_box(page, frame)
                if frame_box and human_click(page, frame_box, rng=rng):
                    return True, f"clicked challenge frame centre for {selector}"
            except Exception:
                continue
    # Some vendors render the button in the main document.
    for text in BUTTON_TEXT_HINTS:
        try:
            locator = page.get_by_text(text, exact=False).first
            if locator.count() == 0:
                continue
            box = locator.bounding_box()
            if box and box.get("width") and human_click(page, box, rng=rng):
                return True, f"clicked '{text}'"
        except Exception:
            continue
    return False, "no clickable challenge element found"


def _frame_box(page: Any, frame: Any) -> dict[str, float] | None:
    try:
        element = frame.frame_element()
        return element.bounding_box()
    except Exception:
        return None


def solve(
    page: Any,
    read_html: Callable[[], str],
    *,
    profile: BypassProfile | None = None,
    deadline: float | None = None,
    on_event: Callable[[Mapping[str, Any]], None] | None = None,
    rng: random.Random | None = None,
) -> SolveResult:
    """Wait for (and if possible clear) the interstitial on the current page.

    ``read_html`` must return the *current* document, so the caller controls how
    the body is extracted.  ``deadline`` is a ``time.monotonic()`` value.
    """

    profile = profile or BypassProfile()
    rng = rng or random.Random()
    started = _now()
    limit = deadline if deadline is not None else started + max(1.0, profile.challenge_wait_seconds)
    notes: list[str] = []
    html = ""
    signal = ProtectionSignal("none")

    def check() -> ProtectionSignal:
        nonlocal html
        try:
            html = read_html() or ""
        except Exception as exc:  # page closed / navigation in flight
            notes.append(f"read failed: {type(exc).__name__}")
            return ProtectionSignal("unknown", "", "", 0, ("read-failed",))
        return classify_html(html)

    signal = check()
    if signal.kind != "challenge":
        return SolveResult(True, html, signal, waited_ms=int((_now() - started) * 1000),
                           reason="no challenge present", notes=notes,
                           cookies=_cookies(page))

    _emit(on_event, {"stage": "challenge-detected", "signal": signal.describe(),
                     "wait_seconds": profile.challenge_wait_seconds})
    passive_until = min(limit, started + 3.0)
    while _now() < passive_until and signal.is_challenge:
        _settle(page, rng)
        signal = check()
    if not signal.is_challenge:
        return SolveResult(True, html, signal, waited_ms=int((_now() - started) * 1000),
                           reason="challenge cleared without interaction", notes=notes,
                           cookies=_cookies(page))

    if not profile.challenge_interactive:
        return SolveResult(False, html, signal, waited_ms=int((_now() - started) * 1000),
                           reason="interactive solving disabled", notes=notes)

    attempts = 0
    while _now() < limit:
        if signal.kind == "login":
            return SolveResult(False, html, signal, waited_ms=int((_now() - started) * 1000),
                               reason="challenge page asks for credentials", notes=notes)
        attempts += 1
        clicked, why = click_challenge(page, rng=rng)
        notes.append(f"attempt {attempts}: {why}")
        _emit(on_event, {"stage": "challenge-click", "attempt": attempts, "clicked": clicked,
                         "detail": why, "signal": signal.describe()})
        if not clicked:
            wander(page, rng=rng)
        _settle(page, rng, extra_ms=rng.randint(900, 2200) if clicked else rng.randint(1200, 2600))
        signal = check()
        if not signal.is_challenge:
            _emit(on_event, {"stage": "challenge-cleared", "attempts": attempts})
            return SolveResult(True, html, signal, waited_ms=int((_now() - started) * 1000),
                               reason="cleared after interaction", notes=notes,
                               cookies=_cookies(page))

    _emit(on_event, {"stage": "challenge-timeout", "attempts": attempts,
                     "signal": signal.describe()})
    return SolveResult(False, html, signal, waited_ms=int((_now() - started) * 1000),
                       reason=f"still challenged after {attempts} interaction(s)", notes=notes)


def _settle(page: Any, rng: random.Random, *, extra_ms: int = 0) -> None:
    """Give the page a moment to finish its challenge round-trip."""

    try:
        page.wait_for_load_state("domcontentloaded", timeout=3000)
    except Exception:
        pass
    try:
        page.wait_for_timeout(extra_ms or rng.randint(350, 900))
    except Exception:
        time.sleep(min(1.0, (extra_ms or 400) / 1000))


def _cookies(page: Any) -> list[dict[str, Any]]:
    try:
        cookies = page.context.cookies()
        return [dict(cookie) for cookie in cookies]
    except Exception:
        return []


def has_challenge_frame(page: Any) -> bool:
    return _find_challenge_frame(page) is not None


__all__ = [
    "CHECKBOX_SELECTORS",
    "SolveResult",
    "click_challenge",
    "has_challenge_frame",
    "human_click",
    "solve",
    "wander",
]

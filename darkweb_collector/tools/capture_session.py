"""Capture a real browser login and hand it to the collector's login broker.

Run this on a machine with a desktop (the analyst's own laptop is the intended
place): it opens a normal Chrome window, waits while the analyst logs in, then
writes a storage-state envelope the collector can import.  Doing the login here
rather than on the server is what gets past managed challenges and captchas —
those want a human and a residential egress.

    python darkweb_collector/tools/capture_session.py darkforums --out darkforums.json

Then, on the collector host:

    python -m darkweb_collector.login_broker import-state darkforums --state-file darkforums.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from playwright.sync_api import sync_playwright

START_URLS = {
    "darkforums": "https://darkforums.as/index.php",
    "breachforums": "https://bf.st/index.php",
    "cracked": "https://cracked.st/index.php",
    "leakforum": "https://leakforum.io/index.php",
    "raidforums": "https://raidforums.im/index.php",
    "spear": "https://spear.st/index.php",
    "xforums": "https://xforums.st/",
    "pwnfrm": "https://pwnforums.st/index.php",
}

LOGGED_IN_MARKERS = ("logout", "action=logout", "account/logout")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture a real forum login as a storage state.")
    parser.add_argument("site", choices=sorted(START_URLS))
    parser.add_argument("--out", default="")
    parser.add_argument("--url", default="")
    parser.add_argument("--timeout", type=int, default=600, help="seconds to wait for the login (default 600)")
    args = parser.parse_args(argv)

    url = args.url or START_URLS[args.site]
    out = Path(args.out or f"{args.site}-session.json")
    print(f"opening {url}")
    print("log in in the window that opens; this script saves the session as soon as it sees the logout link")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=False,
                                             args=["--disable-blink-features=AutomationControlled"])
        context = browser.new_context(locale="en-US")
        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded")
        deadline = time.monotonic() + args.timeout
        logged_in = False
        while time.monotonic() < deadline:
            html = page.content().lower()
            if any(marker in html for marker in LOGGED_IN_MARKERS):
                logged_in = True
                break
            page.wait_for_timeout(1000)
        if not logged_in:
            print("timed out waiting for a logged-in page", file=sys.stderr)
            browser.close()
            return 1
        user_agent = str(page.evaluate("navigator.userAgent"))
        state = context.storage_state()
        browser.close()

    out.write_text(json.dumps({"user_agent": user_agent, "storage_state": state}, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    cookies = len(state.get("cookies", []))
    print(f"saved {out} ({cookies} cookies)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

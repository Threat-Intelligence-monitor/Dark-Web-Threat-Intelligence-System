from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlparse


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Launch a visible browser for platform session login.")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--login-url", required=True)
    parser.add_argument("--homepage-url", required=True)
    parser.add_argument("--user-data-dir", required=True)
    parser.add_argument("--storage-state", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    from playwright.sync_api import sync_playwright
    from darkweb_collector.browser_temp import ensure_browser_temp

    user_data_dir = Path(args.user_data_dir).expanduser().resolve()
    storage_state_path = Path(args.storage_state).expanduser().resolve()
    user_data_dir.mkdir(parents=True, exist_ok=True)
    storage_state_path.parent.mkdir(parents=True, exist_ok=True)

    ensure_browser_temp()
    with sync_playwright() as playwright:  # pragma: no cover - interactive flow
        browser = None
        last_error = None
        for channel in ("msedge", "chrome", None):
            try:
                launch_kwargs = {
                    "headless": False,
                    "args": ["--disable-blink-features=AutomationControlled"],
                }
                if channel:
                    launch_kwargs["channel"] = channel
                browser = playwright.chromium.launch(**launch_kwargs)
                break
            except Exception as exc:
                last_error = exc
                browser = None
        if browser is None:
            raise last_error or RuntimeError(f"unable to launch visible browser for {args.platform} login")
        context_kwargs = {
            "viewport": {"width": 1440, "height": 960},
            "ignore_https_errors": True,
        }
        if storage_state_path.exists():
            context_kwargs["storage_state"] = str(storage_state_path)
        context = browser.new_context(**context_kwargs)
        allowed_hosts = {
            urlparse(args.login_url).netloc.lower(),
            urlparse(args.homepage_url).netloc.lower(),
        }
        noisy_popup_patterns = [
            re.compile(r"https://.*\.udesk\.cn/.*", re.IGNORECASE),
            re.compile(r"https://.*\.s4\.udesk\.cn/.*", re.IGNORECASE),
            re.compile(r"https://.*intercom.*", re.IGNORECASE),
            re.compile(r"https://.*zendesk.*", re.IGNORECASE),
            re.compile(r"https://.*tawk\.to/.*", re.IGNORECASE),
            re.compile(r"https://.*crisp\.chat/.*", re.IGNORECASE),
            re.compile(r"https://.*drift\.com/.*", re.IGNORECASE),
            re.compile(r"https://.*beacon-v2.*", re.IGNORECASE),
        ]

        def _abort_noisy_requests(route) -> None:
            request_url = route.request.url
            if any(pattern.match(request_url) for pattern in noisy_popup_patterns):
                route.abort()
                return
            route.continue_()

        def _handle_popup(popup) -> None:
            try:
                popup.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                pass
            try:
                host = urlparse(popup.url or "").netloc.lower()
            except Exception:
                host = ""
            if host and host not in allowed_hosts and not any(host.endswith(f".{item}") for item in allowed_hosts if item):
                try:
                    popup.close()
                except Exception:
                    pass

        context.route(re.compile(r"https://.*"), _abort_noisy_requests)
        context.on("page", _handle_popup)
        context.add_init_script(
            """
            (() => {
              const noopWindowOpen = () => null;
              try {
                Object.defineProperty(window, 'open', {
                  configurable: true,
                  writable: false,
                  value: noopWindowOpen,
                });
              } catch (e) {
                window.open = noopWindowOpen;
              }
            })();
            """
        )
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(args.login_url, wait_until="domcontentloaded", timeout=45000)
        print(f"[platform-session-login] platform={args.platform} ready: {args.login_url}", flush=True)
        while True:
            try:
                context.storage_state(path=str(storage_state_path))
            except Exception:
                pass
            try:
                pages = context.pages
            except Exception:
                break
            if not pages:
                break
            live_pages = [page for page in pages if not page.is_closed()]
            if not live_pages:
                break
            time.sleep(1.2)
        try:
            context.storage_state(path=str(storage_state_path))
        except Exception:
            pass
        try:
            context.close()
        except Exception:
            pass
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

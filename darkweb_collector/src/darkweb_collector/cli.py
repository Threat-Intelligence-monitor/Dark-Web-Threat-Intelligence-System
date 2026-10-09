from __future__ import annotations

from argparse import ArgumentParser
import json
import subprocess
import sys
import time

from darkweb_collector.bot_assistant import (
    build_markdown_payload,
    build_text_payload,
    load_bot_config,
    post_bot_payload,
    send_intelligence_digest,
)
from darkweb_collector.config import get_site_config, load_site_configs
from darkweb_collector.api_data import build_intelligence_payload
from darkweb_collector.orchestrator import dispatch_seed_job, enqueue_due_sites, run_site_once, show_runs
from darkweb_collector.public_vulnerabilities import sync_public_vulnerability_feed
from darkweb_collector.queueing import build_worker_command, queue_for_seed
from darkweb_collector.ransomware_live import sync_ransomware_live_victims
from darkweb_collector.state_store import get_state_store


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="crawl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-sites")

    run_site_parser = subparsers.add_parser("run-site")
    run_site_parser.add_argument("--site", required=True)
    run_site_parser.add_argument("--once", action="store_true")
    run_site_parser.add_argument("--continuous", action="store_true")
    run_site_parser.add_argument("--interval-seconds", type=int, default=None)

    subparsers.add_parser("enqueue-due")

    worker_parser = subparsers.add_parser("worker")
    worker_parser.add_argument("--queue", required=True)

    show_runs_parser = subparsers.add_parser("show-runs")
    show_runs_parser.add_argument("--limit", type=int, default=20)

    sync_vulns_parser = subparsers.add_parser("sync-public-vulns")
    sync_vulns_parser.add_argument("--sample-file", default=None)
    sync_vulns_parser.add_argument("--limit", type=int, default=300)

    sync_ransomware_parser = subparsers.add_parser("sync-ransomware-live")
    sync_ransomware_parser.add_argument("--limit", type=int, default=0)

    bot_parser = subparsers.add_parser("send-bot-message")
    bot_parser.add_argument("--type", choices=["digest", "text", "markdown"], default="digest")
    bot_parser.add_argument("--content", default="")
    bot_parser.add_argument("--provider", default=None)
    bot_parser.add_argument("--bot-id", default=None)
    bot_parser.add_argument("--chat-id", default=None)
    bot_parser.add_argument("--websocket-url", default=None)
    bot_parser.add_argument("--webhook-url", default=None)
    bot_parser.add_argument("--secret", default=None)
    bot_parser.add_argument("--limit", type=int, default=5)
    bot_parser.add_argument("--dry-run", action="store_true")

    return parser


def _run_list_sites() -> int:
    rows = []
    for config in load_site_configs():
        rows.append(
            {
                "site_name": config.site_name,
                "enabled": config.enabled,
                "profile": config.profile,
                "seed_fetch_mode": config.seed_fetch_mode,
                "detail_fetch_mode": config.detail_fetch_mode,
                "browser_queue": config.browser_queue,
                "max_concurrent_details": config.max_concurrent_details,
                "seed_urls": list(config.seed_urls),
            }
        )
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def _run_site_once(site_name: str) -> int:
    result = run_site_once(site_name)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _run_site_continuous(site_name: str, interval_seconds: int | None) -> int:
    config = get_site_config(site_name)
    sleep_seconds = interval_seconds or config.effective_interval_seconds
    while True:
        result = run_site_once(site_name)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print(
            json.dumps(
                {
                    "site_name": site_name,
                    "next_run_in_seconds": sleep_seconds,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        time.sleep(sleep_seconds)


def _enqueue_due() -> int:
    try:
        from darkweb_collector.tasks import crawl_seed, enqueue_ransomware_live_sync
    except ImportError as exc:
        raise RuntimeError("Celery is required to enqueue queued crawl jobs") from exc

    def seed_dispatcher(config) -> str | None:
        queue_name = queue_for_seed(config)
        return dispatch_seed_job(
            config,
            lambda job_id: crawl_seed.apply_async(
                kwargs={"site_name": config.site_name, "force": False},
                queue=queue_name,
                task_id=job_id,
            ),
        )

    dispatched = enqueue_due_sites(seed_dispatcher=seed_dispatcher, state_store=get_state_store(prefer_redis=True))
    ransomware_job_id = enqueue_ransomware_live_sync()
    if ransomware_job_id:
        dispatched.append(
            {
                "site_name": "ransomware_live",
                "job_id": ransomware_job_id,
                "queue_name": "seed_http",
            }
        )
    print(json.dumps(dispatched, ensure_ascii=False, indent=2))
    return 0


def _run_worker(queue_name: str) -> int:
    command = build_worker_command(queue_name)
    completed = subprocess.run(command, check=False)
    return int(completed.returncode)


def _show_runs(limit: int) -> int:
    print(json.dumps(show_runs(limit=limit), ensure_ascii=False, indent=2))
    return 0


def _sync_public_vulns(sample_file: str | None, limit: int) -> int:
    print(
        json.dumps(
            sync_public_vulnerability_feed(
                sample_file=sample_file,
                limit=limit,
                refresh_normalized=False,
            ),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _sync_ransomware_live(limit: int) -> int:
    print(
        json.dumps(
            sync_ransomware_live_victims(limit=limit, refresh_normalized=False),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _send_bot_message(args) -> int:
    config = load_bot_config(
        provider=args.provider,
        bot_id=args.bot_id,
        chat_id=args.chat_id,
        websocket_url=args.websocket_url,
        webhook_url=args.webhook_url,
        secret=args.secret,
        dry_run=args.dry_run or None,
    )
    if args.type == "digest":
        payload = build_intelligence_payload()
        result = send_intelligence_digest(payload, config=config, limit=args.limit)
    else:
        if not args.content:
            raise ValueError("--content is required for text or markdown messages")
        message_payload = build_text_payload(args.content) if args.type == "text" else build_markdown_payload(args.content)
        result = post_bot_payload(message_payload, config)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "list-sites":
        return _run_list_sites()
    if args.command == "run-site":
        if args.once and args.continuous:
            parser.error("run-site cannot use --once and --continuous together")
        if args.continuous:
            return _run_site_continuous(args.site, args.interval_seconds)
        if args.once:
            return _run_site_once(args.site)
        parser.error("run-site requires either --once or --continuous")
    if args.command == "enqueue-due":
        return _enqueue_due()
    if args.command == "worker":
        return _run_worker(args.queue)
    if args.command == "show-runs":
        return _show_runs(args.limit)
    if args.command == "sync-public-vulns":
        return _sync_public_vulns(args.sample_file, args.limit)
    if args.command == "sync-ransomware-live":
        return _sync_ransomware_live(args.limit)
    if args.command == "send-bot-message":
        return _send_bot_message(args)
    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

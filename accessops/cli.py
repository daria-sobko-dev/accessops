"""Command line interface: python -m accessops <command>."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

import httpx
import psycopg

from accessops import n8n
from accessops.api import bootstrap_secrets
from accessops.audit import AuditLog
from accessops.catalog import Catalog, load_catalog
from accessops.clock import utcnow
from accessops.config import PROJECT_ROOT, Settings, load_settings
from accessops.envfile import ENV_FILE, read_env, set_env_var
from accessops.errors import (
    AccessOpsError,
    BusyError,
    ConfigError,
    InvalidInputError,
    PolicyDeniedError,
)
from accessops.grants import GrantStore
from accessops.linux import SERVICE_KEY, bootstrap_service_key
from accessops.outcome import Outcome
from accessops.reports import (
    Report,
    access_report,
    drift_report,
    expiring_report,
    format_table,
    privileged_report,
    write_csv,
)
from accessops.service import SYSTEMS
from accessops.telegram import fetch_updates, private_chats
from accessops.ttl import (
    DISPLAY_TZ,
    DISPLAY_TZ_NAME,
    format_remaining,
    format_time,
    parse_ttl,
)
from accessops.wiring import build_service, open_backends

EXIT_OK, EXIT_ERROR, EXIT_DENIED, EXIT_BUSY = 0, 1, 2, 3


def _default_actor() -> str:
    return os.environ.get("ACCESSOPS_ACTOR") or getpass.getuser()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m accessops", description="Grant, audit and revoke access."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "ssh-bootstrap", help="create the Ansible service SSH key for linux-target (run once)"
    )
    api_bootstrap = sub.add_parser(
        "api-bootstrap", help="put the accessops-api token and Ansible key secret into .env"
    )
    api_bootstrap.add_argument("--rotate", action="store_true", help="make a new API token")
    sub.add_parser("n8n-setup", help="load the AccessOps workflows and credentials into n8n")
    sub.add_parser("n8n-export", help="export the workflows to n8n/workflows (no secrets)")
    sub.add_parser(
        "telegram-setup", help="find your Telegram chat id (write to the bot first), save to .env"
    )
    sub.add_parser(
        "init", help="create appdb, group roles, RabbitMQ vhost, audit table; check linux-target"
    )

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("subject", help="user name (lowercase latin letters, digits, _)")
        p.add_argument("--system", choices=[*SYSTEMS, "all"], default="all")
        p.add_argument("--actor", default=_default_actor(), help="who performs the change")
        p.add_argument("--ticket", dest="ticket_id", help="ticket id, e.g. ACC-42")
        p.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")

    grant = sub.add_parser("grant", help="grant a catalog role to a user")
    common(grant)
    grant.add_argument("role", help="role name from roles.yaml")
    grant.add_argument("--approved-by", help="human approver (required for privileged roles)")
    grant.add_argument("--ttl", help="temporary access, e.g. 30m, 8h, 3d (required: privileged)")

    revoke = sub.add_parser("revoke", help="revoke access and delete the user")
    common(revoke)

    sub.add_parser("list", help="show who has which role right now (asks the systems)")

    cleanup = sub.add_parser("cleanup", help="revoke access whose --ttl has expired")
    cleanup.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")

    report = sub.add_parser("report", help="reports for people and spreadsheets")
    report.add_argument("kind", choices=["access", "expiring", "privileged", "drift"])
    report.add_argument("--within", default="24h", help="window for 'expiring', e.g. 24h, 7d")
    report.add_argument("--csv", type=Path, help="also save the report as CSV to this path")

    audit = sub.add_parser("audit", help="show the latest audit records")
    audit.add_argument("--limit", type=int, default=20)
    return parser


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _print_outcomes(action: str, subject: str, outcomes: list[Outcome], dry_run: bool) -> None:
    if dry_run:
        print("DRY RUN: nothing was changed.")
    for o in outcomes:
        if dry_run:
            status = "would change" if o.changed else "no change needed"
        else:
            status = "changed" if o.changed else "no change (already in desired state)"
        role = f" role={o.role}" if o.role else ""
        print(f"[{o.system}] {action} {subject}{role}: {status}")
        for step in o.steps:
            print(f"  - {step}")
        if o.credentials_file is not None:
            print(f"  credentials file: {_display_path(o.credentials_file)}")
    if action == "grant" and outcomes:
        expires_at = outcomes[0].expires_at
        if expires_at is None:
            print("Access is permanent (no --ttl).")
        else:
            left = format_remaining(expires_at, utcnow())
            print(f"Access expires at {format_time(expires_at)} (in {left}).")


def _systems(choice: str) -> tuple[str, ...]:
    return SYSTEMS if choice == "all" else (choice,)


def cmd_ssh_bootstrap(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    for step in bootstrap_service_key():
        print(f"[linux] {step}")
    return EXIT_OK


def cmd_api_bootstrap(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    for step in bootstrap_secrets(ENV_FILE, SERVICE_KEY, rotate=args.rotate):
        print(f"[api] {step}")
    print("[api] next: docker compose up -d --build accessops-api")
    return EXIT_OK


def cmd_n8n_setup(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    for step in n8n.setup(read_env(), n8n.N8nContainer()):
        print(f"[n8n] {step}")
    return EXIT_OK


def cmd_n8n_export(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    for step in n8n.export(read_env(), n8n.N8nContainer()):
        print(f"[n8n] {step}")
    print(f"[n8n] file: {_display_path(n8n.WORKFLOWS_FILE)}")
    return EXIT_OK


def cmd_telegram_setup(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    token = read_env().get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise ConfigError("TELEGRAM_BOT_TOKEN is not set in .env.")
    chats = private_chats(fetch_updates(token))
    if not chats:
        raise ConfigError(
            "No private messages to the bot found. Write any message to the bot and run again."
        )
    if len(chats) > 1:
        names = ", ".join(chat.label for chat in chats)
        raise ConfigError(f"Several people wrote to the bot ({names}); expected exactly one.")
    set_env_var(
        ENV_FILE, "TELEGRAM_CHAT_ID", str(chats[0].id), "Telegram chat for AccessOps alerts"
    )
    print(f"[telegram] found the private chat with {chats[0].label}")
    print("[telegram] chat id saved to .env as TELEGRAM_CHAT_ID")
    return EXIT_OK


def cmd_init(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    AuditLog(settings).ensure_schema()
    print("[audit] table access_audit is ready (append-only trigger installed)")
    GrantStore(settings).ensure_schema()
    print("[grants] table access_grants is ready (one active grant per user and system)")
    with open_backends(settings, catalog) as backends:
        for name, backend in backends.items():
            for step in backend.setup():
                print(f"[{name}] {step}")
    return EXIT_OK


def cmd_grant(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    with open_backends(settings, catalog) as backends:
        outcomes = build_service(settings, catalog, backends).grant(
            subject=args.subject,
            role_name=args.role,
            actor=args.actor,
            approved_by=args.approved_by,
            ticket_id=args.ticket_id,
            ttl=args.ttl,
            systems=_systems(args.system),
            dry_run=args.dry_run,
        )
    _print_outcomes("grant", args.subject, outcomes, args.dry_run)
    return EXIT_OK


def cmd_revoke(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    with open_backends(settings, catalog) as backends:
        outcomes = build_service(settings, catalog, backends).revoke(
            subject=args.subject,
            actor=args.actor,
            ticket_id=args.ticket_id,
            systems=_systems(args.system),
            dry_run=args.dry_run,
        )
    _print_outcomes("revoke", args.subject, outcomes, args.dry_run)
    return EXIT_OK


def cmd_list(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    rows = []
    with open_backends(settings, catalog) as backends:
        for name, backend in backends.items():
            rows += [(subject, name, role or "-") for subject, role in backend.list_assignments()]
    if not rows:
        print("No access granted by AccessOps.")
        return EXIT_OK
    print(f"{'SUBJECT':<20} {'SYSTEM':<10} ROLE")
    for subject, system, role in sorted(rows):
        print(f"{subject:<20} {system:<10} {role}")
    return EXIT_OK


def _fit(value: str | None, width: int) -> str:
    text = value or "-"
    return text if len(text) <= width else text[: width - 1] + "~"


def cmd_audit(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    records = AuditLog(settings).recent(args.limit)
    if not records:
        print("Audit log is empty.")
        return EXIT_OK
    time_title = f"TIME ({DISPLAY_TZ_NAME})"
    header = (
        f"{'ID':>4} {time_title:<19} {'ACTOR':<14} {'APPROVER':<9} {'ACTION':<7} "
        f"{'SYSTEM':<9} {'SUBJECT':<12} {'ROLE':<13} {'TICKET':<8} {'RESULT':<8} DETAILS"
    )
    print(header)
    for r in reversed(records):
        details = r["details"]
        summary = (
            details.get("reason")
            or details.get("error")
            or json.dumps({k: v for k, v in details.items() if k != "steps"})
        )
        if len(summary) > 70:
            summary = summary[:67] + "..."
        local = r["created_at"].astimezone(DISPLAY_TZ)
        print(
            f"{r['id']:>4} {local:%Y-%m-%d %H:%M:%S} {_fit(r['actor'], 14):<14} "
            f"{_fit(r['approved_by'], 9):<9} {r['action']:<7} {r['system']:<9} "
            f"{_fit(r['subject'], 12):<12} {_fit(r['role'], 13):<13} {_fit(r['ticket_id'], 8):<8} "
            f"{r['result']:<8} {summary}"
        )
    return EXIT_OK


def cmd_cleanup(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    with open_backends(settings, catalog) as backends:
        items = build_service(settings, catalog, backends).cleanup(dry_run=args.dry_run)
    if args.dry_run:
        print("DRY RUN: nothing was changed.")
    if not items:
        print(f"Nothing to clean up: no expired access at {format_time(utcnow())}.")
        return EXIT_OK
    for item in items:
        g = item.grant
        print(
            f"[{g.system}] {g.subject} role={g.role} expired {format_time(g.expires_at)}: "
            f"{item.result}"
        )
        for step in item.steps:
            print(f"  - {step}")
    failed = [i for i in items if i.result == "error"]
    if failed:
        print(f"{len(failed)} system(s) failed; those grants stay active for the next cleanup.")
        return EXIT_ERROR
    return EXIT_OK


def _build_report(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> Report:
    now = utcnow()
    grants = GrantStore(settings).active()
    if args.kind == "access":
        return access_report(grants, catalog, now)
    if args.kind == "expiring":
        try:
            within = parse_ttl(args.within)
        except ValueError as exc:
            raise InvalidInputError(f"Invalid --within: {exc}.") from None
        return expiring_report(grants, catalog, now, within)
    if args.kind == "privileged":
        return privileged_report(grants, catalog, now)
    with open_backends(settings, catalog) as backends:
        inventories = {name: backend.inventory() for name, backend in backends.items()}
    return drift_report(grants, inventories)


def cmd_report(settings: Settings, catalog: Catalog, args: argparse.Namespace) -> int:
    report = _build_report(settings, catalog, args)
    print(format_table(report))
    if args.csv is not None:
        path = write_csv(report, args.csv)
        print(f"CSV saved: {_display_path(path)} ({len(report.rows)} rows + header)")
    return EXIT_OK


COMMANDS = {
    "ssh-bootstrap": cmd_ssh_bootstrap,
    "api-bootstrap": cmd_api_bootstrap,
    "n8n-setup": cmd_n8n_setup,
    "n8n-export": cmd_n8n_export,
    "telegram-setup": cmd_telegram_setup,
    "init": cmd_init,
    "grant": cmd_grant,
    "revoke": cmd_revoke,
    "list": cmd_list,
    "cleanup": cmd_cleanup,
    "report": cmd_report,
    "audit": cmd_audit,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings()
        catalog = load_catalog(settings.catalog_path)
        return COMMANDS[args.command](settings, catalog, args)
    except PolicyDeniedError as exc:
        print(f"DENIED: {exc}", file=sys.stderr)
        return EXIT_DENIED
    except BusyError as exc:
        print(f"BUSY: {exc}", file=sys.stderr)
        return EXIT_BUSY
    except AccessOpsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (psycopg.Error, httpx.HTTPError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR

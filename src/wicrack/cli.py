"""Typer CLI — the single entry point for every workflow."""

from __future__ import annotations

from pathlib import Path

import typer
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wicrack import __version__
from wicrack.config import Settings
from wicrack.logging import setup_logging

app = typer.Typer(
    help=(
        "WiCrackAgent — automated wireless security assessment. "
        "AUTHORIZED USE ONLY: networks you own or are contracted to test."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)
assets_app = typer.Typer(help="Download wordlists and rules")
vault_app = typer.Typer(help="Encrypted results vault")
app.add_typer(assets_app, name="assets")
app.add_typer(vault_app, name="vault")
console = Console()

_BANNER = Panel.fit(
    f"[bold green]WiCrackAgent v{__version__}[/bold green]\n"
    "[dim]Automated wireless security assessment — GPU + CPU dual engine[/dim]\n"
    "[red]AUTHORIZED-USE ONLY[/red]",
    border_style="green",
)


def _base_settings(
    dry_run: bool = False,
    yes: bool = False,
    engine: str | None = None,
) -> Settings:
    settings = Settings()
    if engine:
        settings.engine = engine  # type: ignore[assignment]
    if yes:
        settings.assume_yes = True
    if dry_run:
        settings.dry_run = True
    settings.ensure_dirs()
    setup_logging(settings.log_dir)
    console.print(_BANNER)
    return settings


def _pick_engine(settings):
    from wicrack.engines.selector import select_engine

    return select_engine(settings)


@app.command()
def serve(
    host: str = typer.Option(None, help="Bind address (default from config)"),
    port: int = typer.Option(None, help="Bind port (default from config)"),
    engine: str | None = typer.Option(None, "--engine", help="auto|hashcat|john"),
    dry_run: bool = typer.Option(False, help="Log commands, run nothing"),
) -> None:
    """Start the live web console (upload, configure, monitor, report)."""
    settings = _base_settings(dry_run=dry_run, engine=engine)
    settings.load_web_overrides()
    if host:
        settings.web_host = host
    if port:
        settings.web_port = port
    password = settings.ensure_web_password()

    store = _make_store(settings)
    eng = _pick_engine(settings)
    from wicrack.core.jobqueue import JobManager
    from wicrack.notify import make_notifier

    mgr = JobManager(settings, eng, store, interactive=False, notifier=make_notifier(settings))
    mgr.start_worker()

    from wicrack.web.app import create_app

    webapp = create_app(settings, job_manager=mgr, store=store)

    logger.info(
        "Web console password: [bold]{}[/] (stored in {} — change it in Settings!)",
        password,
        settings.web_state_path,
    )
    logger.info("Web console: http://localhost:{} — bind {}", settings.web_port, settings.web_host)
    try:
        webapp.run(
            host=settings.web_host, port=settings.web_port, use_reloader=False, threaded=True
        )
    finally:
        eng.terminate_all()


@app.command()
def crack(
    folder: Path = typer.Option(
        None, "--folder", "-f", help="Folder containing .cap/.pcap/.pcapng"
    ),
    engine: str | None = typer.Option(None, "--engine", help="auto|hashcat|john"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Approve heavy stages"),
    dry_run: bool = typer.Option(False, help="Show the plan without attacking"),
    no_benchmark: bool = typer.Option(False, help="Skip GPU benchmark"),
) -> None:
    """Run the full CLI pipeline over a capture folder."""
    settings = _base_settings(dry_run=dry_run, yes=yes, engine=engine)
    if folder:
        settings.capture_dir = folder

    from wicrack.capture.converter import scan_captures

    captures = scan_captures(settings.capture_dir)
    if not captures:
        logger.warning(
            "No capture files in {} — dropping them into the web console is easier.",
            settings.capture_dir,
        )
        raise typer.Exit(0)
    if dry_run:
        table = Table(title="DRY-RUN plan")
        table.add_column("#")
        table.add_column("capture")
        for i, cap in enumerate(captures, 1):
            table.add_row(str(i), str(cap))
        console.print(table)
        raise typer.Exit(0)

    from wicrack.engines import hardware

    if settings.benchmark:
        speed = hardware.benchmark_speed(settings)
        if speed:
            settings.est_speed = speed

    store = _make_store(settings)
    eng = _pick_engine(settings)
    from wicrack.core.jobqueue import JobManager
    from wicrack.notify import make_notifier

    mgr = JobManager(settings, eng, store, interactive=True, notifier=make_notifier(settings))
    try:
        mgr.start_worker()
        mgr.submit(captures)
        mgr.queue.join()
    except KeyboardInterrupt:
        logger.warning("Interrupted — stopping worker")
        mgr.stop()
        raise typer.Exit(130) from None
    finally:
        eng.terminate_all()

    _print_summary(store, settings)


@app.command()
def scan(
    folder: Path = typer.Option(None, "--folder", "-f", help="Capture folder to inspect"),
) -> None:
    """Convert captures and list every wireless target found."""
    settings = _base_settings()
    if folder:
        settings.capture_dir = folder
    from wicrack.capture.converter import convert_to_22000, scan_captures
    from wicrack.capture.parser import parse_22000_file

    table = Table(title=f"Targets in {settings.capture_dir}")
    for col in ("capture", "type", "essid", "bssid"):
        table.add_column(col)
    for cap in scan_captures(settings.capture_dir):
        hc = convert_to_22000(cap)
        if not hc:
            table.add_row(cap.name, "-", "-", "-")
            continue
        for t in parse_22000_file(hc):
            table.add_row(cap.name, t["type"], t["essid"] or "?", t["ap"])
    console.print(table)


@app.command()
def bench(
    no_cache: bool = typer.Option(False, help="Force a fresh benchmark"),
) -> None:
    """Benchmark the cracking engine (WPA mode 22000)."""
    settings = _base_settings(dry_run=True)
    from wicrack.engines import hardware

    gpus = hardware.gpu_count()
    speed = hardware.benchmark_speed(settings, use_cache=not no_cache)
    table = Table(title="Hardware benchmark")
    table.add_column("metric")
    table.add_column("value")
    table.add_row("GPU devices", str(gpus))
    table.add_row("WPA speed", f"{speed:,} H/s" if speed else "n/a")
    console.print(table)


@app.command()
def report(
    fmt: str = typer.Option("html", "--format", help="html | evidence"),
    out: Path = typer.Option(None, "--out", help="Output file path"),
    engagement: str = typer.Option("", help="Engagement name for the report"),
    include_plaintext: bool = typer.Option(
        False, help="Evidence: include plaintext keys (default: sha256 only)"
    ),
) -> None:
    """Generate a client-ready HTML report or an evidence JSON file."""
    settings = _base_settings(dry_run=True)
    store = _make_store(settings)
    out = out or settings.report_dir / (
        "assessment_report.html" if fmt == "html" else "evidence.json"
    )
    if fmt == "html":
        from wicrack.reporting import generate_html_report

        path = generate_html_report(store, settings, out, engagement=engagement)
    elif fmt == "evidence":
        from wicrack.reporting import export_evidence

        path = export_evidence(store, out, include_plaintext=include_plaintext)
    else:
        raise typer.BadParameter("format must be html or evidence")
    console.print(f"[green]✓[/] Written: [bold]{path}[/]")


@assets_app.command("download")
def assets_download(
    name: str = typer.Argument(None, help="rockyou | ortra (empty = all)"),
) -> None:
    """Download wordlists / rules from verified upstream URLs."""
    settings = _base_settings(dry_run=True)
    from wicrack.assets import download_all, download_asset

    if name is None:
        download_all(settings)
    else:
        download_asset(name, settings)


@vault_app.command("export")
def vault_export() -> None:
    """Export every result into an encrypted vault file."""
    import getpass

    settings = _base_settings(dry_run=True)
    store = _make_store(settings)
    master = getpass.getpass("Master password for the vault: ")
    if not master:
        raise typer.BadParameter("empty master password")
    from wicrack.vault import encrypt_store

    path = encrypt_store(store, settings, master)
    console.print(f"[green]✓[/] Vault: [bold]{path}[/]")


@vault_app.command("read")
def vault_read() -> None:
    """Decrypt and display a vault file."""
    import getpass

    settings = _base_settings(dry_run=True)
    master = getpass.getpass("Master password: ")
    from wicrack.vault import read_vault

    rows = read_vault(settings.data_dir / "vault.bin", settings.data_dir / "vault.salt", master)
    table = Table(title=f"{len(rows)} result(s) from vault")
    for col in ("time", "essid", "key", "stage"):
        table.add_column(col)
    for r in rows:
        table.add_row(r.get("ts", ""), r.get("essid", ""), r.get("key", ""), r.get("stage", ""))
    console.print(table)


@app.command()
def selftest() -> None:
    """Verify tools, logic, and an end-to-end WPA crack (first run!)."""
    settings = _base_settings(dry_run=True)
    from wicrack.selftest import run_self_test

    ok = run_self_test(settings)
    raise typer.Exit(0 if ok else 1)


@app.command()
def version() -> None:
    """Print the installed version."""
    console.print(f"WiCrackAgent v{__version__}")


def _make_store(settings):
    from wicrack.core.store import Store

    return Store(settings.db_path)


def _print_summary(store, settings) -> None:
    analytics = store.analytics()
    if analytics:
        top = analytics["top_stages"][0]["stage"] if analytics["top_stages"] else "-"
        console.print(
            Panel.fit(
                f"cracked: [bold green]{analytics['total']}[/]  "
                f"avg len: {analytics['avg_len']}  top stage: {top}",
                title="Summary",
            )
        )
    logger.info(
        "Artifacts: {} | {} | {}",
        settings.text_report_path,
        settings.csv_export_path,
        settings.db_path,
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()

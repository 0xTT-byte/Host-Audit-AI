"""CLI entrypoint for host-audit-ai."""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Annotated, Literal

import typer
from rich.console import Console
from rich.table import Table

import host_audit_ai.engine.rules  # noqa: F401 Ensure all rules are loaded
from host_audit_ai import __version__
from host_audit_ai.collectors import (
    CollectorTransport,
    CollectorTransportError,
    LocalTransport,
    OfflineTransport,
    ProvisioningError,
    SSHTarget,
    SSHTransport,
    render_target_setup_bundle,
    save_capture,
)
from host_audit_ai.engine import (
    RuleRegistry,
    evaluate,
    load_baseline,
    load_waivers,
)
from host_audit_ai.exporters import SUPPORTED_EXPORT_FORMATS, export_json, export_report
from host_audit_ai.models.finding import DriftStatus, Finding, Severity
from host_audit_ai.models.report import AuditReport, RunDiff
from host_audit_ai.parsers import parse_envelope
from host_audit_ai.storage import AuditStore, diff_from_store, diff_runs

app = typer.Typer(
    name="host-audit",
    help="Host Audit AI: Security Auditing and Multi-Agent Triage.",
    no_args_is_help=True,
)

_FAIL_ON_WEIGHTS: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

_SEV_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
    Severity.HIGH: "[red]HIGH[/red]",
    Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
    Severity.LOW: "[blue]LOW[/blue]",
    Severity.INFO: "[dim]INFO[/dim]",
}


def version_callback(value: bool) -> None:
    """Print package version and exit."""
    if value:
        typer.echo(f"host-audit-ai v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Host Audit AI CLI."""


@app.command()
def collect(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Collection target: 'local', 'ssh://[user@]host[:port]', or 'file:///path/to/dump'",
        ),
    ] = "local",
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Output path to save collection envelope or raw capture.",
        ),
    ] = None,
    format_opt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: 'envelope' (JSON) or 'raw' (framed text).",
        ),
    ] = "envelope",
    identity: Annotated[
        Path | None,
        typer.Option(
            "--identity",
            "-i",
            help="Path to SSH private key identity file.",
        ),
    ] = None,
    accept_new_host_key: Annotated[
        bool,
        typer.Option(
            "--accept-new-host-key",
            help="Accept new SSH host keys (default is strict checking).",
        ),
    ] = False,
    timeout: Annotated[
        int,
        typer.Option(
            "--timeout",
            help="Execution timeout in seconds.",
        ),
    ] = 120,
) -> None:
    """Run agentless host collection script and generate raw envelope."""
    if format_opt not in ("envelope", "raw"):
        typer.secho(
            f"Error: Invalid format '{format_opt}'. Must be 'envelope' or 'raw'.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    fmt: Literal["envelope", "raw"] = "envelope" if format_opt == "envelope" else "raw"
    known_hosts: Literal["strict", "accept-new"] = "accept-new" if accept_new_host_key else "strict"

    start_time = time.monotonic()
    transport: CollectorTransport

    try:
        if target == "local":
            transport = LocalTransport(timeout_seconds=timeout)
        elif target.startswith("ssh://"):
            ssh_target = SSHTarget.from_uri(target)
            transport = SSHTransport(
                target=ssh_target,
                identity_file=identity,
                known_hosts_policy=known_hosts,
                timeout_seconds=timeout,
            )
        elif target.startswith("file://") or Path(target).is_file():
            clean_path = target[7:] if target.startswith("file://") else target
            transport = OfflineTransport(input_path=Path(clean_path))
        else:
            typer.secho(
                f"Error: Unsupported or non-existent target '{target}'. "
                "Expected 'local', 'ssh://[user@]host[:port]', or 'file:///path/to/capture'.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        raw_bytes, envelope = transport.collect()
    except typer.Exit:
        raise
    except CollectorTransportError as e:
        typer.secho(f"Transport error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    except Exception as e:
        typer.secho(f"Collection error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    elapsed = time.monotonic() - start_time

    diag = (
        f"[host-audit] Host: {envelope.hostname} | EUID: {envelope.euid} | "
        f"Degraded: {envelope.degraded_mode} | Sections: {len(envelope.sections)} | "
        f"Elapsed: {elapsed:.2f}s"
    )
    typer.echo(diag, err=True)

    if out is not None:
        save_capture(raw_bytes, envelope, out, fmt=fmt)
        typer.echo(f"[host-audit] Saved {fmt} to {out}", err=True)
    else:
        if fmt == "envelope":
            typer.echo(envelope.model_dump_json(indent=2))
        else:
            sys.stdout.buffer.write(raw_bytes)
            sys.stdout.buffer.flush()


def _render_scan_rich(report: AuditReport, parse_warning_count: int) -> None:
    console = Console()
    if report.degraded_mode:
        console.print(
            "[bold yellow]WARN: Collector ran in degraded mode (non-root EUID). "
            "Some privileged audit telemetry was unavailable.[/bold yellow]\n"
        )

    if parse_warning_count:
        console.print(f"[dim]Parse warnings recorded: {parse_warning_count}[/dim]\n")

    table = Table(title=f"Host Audit Report: {report.hostname} ({report.baseline_name})")
    table.add_column("Rule ID", style="bold cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Target", style="green")
    table.add_column("Status / Waiver", style="yellow")
    table.add_column("Evidence Snippet")

    for f in report.findings:
        sev_label = _SEV_COLORS.get(f.severity, f.severity.value)
        status_label = f.drift_status.value if f.drift_status else "ACTIVE"
        if f.drift_status == DriftStatus.WAIVED and f.waiver_reason:
            status_label = f"[dim]WAIVED ({f.waiver_reason})[/dim]"
        elif f.drift_status == DriftStatus.WAIVER_EXPIRED:
            status_label = "[bold red]WAIVER_EXPIRED[/bold red]"

        ev_snippet = f.evidence[0].snippet if f.evidence else f.actual
        if len(ev_snippet) > 80:
            ev_snippet = ev_snippet[:77] + "..."

        table.add_row(f.rule_id, sev_label, f.category, f.target, status_label, ev_snippet)

    console.print(table)

    if report.exposure_chains:
        chain_table = Table(title=f"Correlated Exposure Chains ({len(report.exposure_chains)})")
        chain_table.add_column("Severity", no_wrap=True)
        chain_table.add_column("Title", style="bold")
        chain_table.add_column("Attack / Exposure Flow")
        for c in report.exposure_chains:
            sev_label = _SEV_COLORS.get(c.severity, c.severity.value)
            flow = " -> ".join(f"{n.node_type}:{n.label}" for n in c.nodes)
            chain_table.add_row(sev_label, c.title, flow)
        console.print(chain_table)

    console.print(
        f"\n[bold]Total Findings:[/bold] {report.summary.total_findings} active "
        f"([red]{report.summary.counts_by_severity.get(Severity.CRITICAL, 0)} Critical[/red], "
        f"[yellow]{report.summary.counts_by_severity.get(Severity.HIGH, 0)} High[/yellow], "
        f"{report.summary.counts_by_severity.get(Severity.MEDIUM, 0)} Medium) | "
        f"[cyan]{report.summary.exposure_chain_count} Chains[/cyan] | "
        f"[dim]{report.summary.waived_count} Waived[/dim] | "
        f"[bold red]{report.summary.expired_waiver_count} Expired Waivers[/bold red]"
    )


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Audit target: 'local', 'ssh://[user@]host[:port]', or 'file:///path/to/capture'",
        ),
    ] = "local",
    baseline_path: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            "-b",
            help="Path to custom baseline YAML policy file.",
        ),
    ] = None,
    waivers_path: Annotated[
        Path | None,
        typer.Option(
            "--waivers",
            "-w",
            help="Path to waivers YAML exception file.",
        ),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Failure severity gate: 'critical', 'high', 'medium', 'low', or 'info'.",
        ),
    ] = "high",
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Path to write formatted output (or canonical AuditReport JSON in rich mode).",
        ),
    ] = None,
    format_opt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: 'rich', 'json', 'sarif', 'markdown', or 'ai-bundle'.",
        ),
    ] = "rich",
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Alias for '--format json'.",
        ),
    ] = False,
    db_path: Annotated[
        Path | None,
        typer.Option(
            "--db",
            help="Override SQLite audit database path.",
        ),
    ] = None,
    no_save: Annotated[
        bool,
        typer.Option(
            "--no-save",
            help="Do not persist this run to the SQLite audit database.",
        ),
    ] = False,
    identity: Annotated[
        Path | None,
        typer.Option(
            "--identity",
            "-i",
            help="Path to SSH private key identity file.",
        ),
    ] = None,
    accept_new_host_key: Annotated[
        bool,
        typer.Option(
            "--accept-new-host-key",
            help="Accept new SSH host keys (default is strict checking).",
        ),
    ] = False,
    timeout: Annotated[
        int,
        typer.Option(
            "--timeout",
            help="Execution timeout in seconds.",
        ),
    ] = 120,
) -> None:
    """Parse raw envelope, evaluate baseline policy, and generate audit findings."""
    effective_format = "json" if json_output else format_opt.strip().lower()
    valid_scan_formats = ("rich", *SUPPORTED_EXPORT_FORMATS)
    if effective_format not in valid_scan_formats:
        typer.secho(
            f"Error: Invalid format '{effective_format}'. "
            f"Must be one of: {', '.join(valid_scan_formats)}.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    if fail_on.lower() not in _FAIL_ON_WEIGHTS:
        typer.secho(
            f"Error: Invalid --fail-on severity '{fail_on}'. "
            "Must be one of: critical, high, medium, low, info.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    known_hosts: Literal["strict", "accept-new"] = "accept-new" if accept_new_host_key else "strict"

    try:
        # 1. Transport & Collect
        transport: CollectorTransport
        if target == "local":
            transport = LocalTransport(timeout_seconds=timeout)
        elif target.startswith("ssh://"):
            ssh_target = SSHTarget.from_uri(target)
            transport = SSHTransport(
                target=ssh_target,
                identity_file=identity,
                known_hosts_policy=known_hosts,
                timeout_seconds=timeout,
            )
        elif target.startswith("file://") or Path(target).is_file():
            clean_path = target[7:] if target.startswith("file://") else target
            transport = OfflineTransport(input_path=Path(clean_path))
        else:
            typer.secho(
                f"Error: Unsupported or non-existent target '{target}'.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        _, envelope = transport.collect()

        # 2. Parse Envelope into HostSnapshot
        snapshot = parse_envelope(envelope)

        # 3. Load Baseline and Waivers
        baseline = load_baseline(baseline_path)
        waivers = load_waivers(waivers_path)

        # 4. Evaluate Snapshot against Baseline (including exposure correlation)
        report = evaluate(snapshot, baseline, waivers=waivers)

        # 5. Persist run + snapshot unless --no-save
        if not no_save:
            with AuditStore(db_path=db_path) as store:
                saved_run_id = store.save_run(report, snapshot=snapshot)
                if saved_run_id != report.run_id:
                    report = report.model_copy(update={"run_id": saved_run_id})
                typer.echo(
                    f"[host-audit] Saved run {saved_run_id} to {store.db_path}",
                    err=True,
                )
    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Scan execution error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    # 6. Output handling
    if effective_format == "rich":
        if out is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(export_json(report), encoding="utf-8")
            typer.echo(f"[host-audit] Saved AuditReport JSON to {out}", err=True)
        _render_scan_rich(report, len(snapshot.parse_warnings))
    else:
        rendered = export_report(report, effective_format, snapshot=snapshot)
        if out is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(rendered, encoding="utf-8")
            typer.echo(f"[host-audit] Saved {effective_format} output to {out}", err=True)
        typer.echo(rendered)

    # 7. Exit code gate evaluation
    threshold_weight = _FAIL_ON_WEIGHTS[fail_on.lower()]
    active_violating_findings = [
        f
        for f in report.findings
        if f.drift_status != DriftStatus.WAIVED and f.severity.weight >= threshold_weight
    ]

    if active_violating_findings:
        raise typer.Exit(code=2)

    raise typer.Exit(code=0)


@app.command()
def runs(
    host: Annotated[
        str | None,
        typer.Option(
            "--host",
            help="Filter runs by hostname or host_id.",
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            help="Maximum number of runs to display.",
        ),
    ] = 20,
    db_path: Annotated[
        Path | None,
        typer.Option(
            "--db",
            help="Override SQLite audit database path.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output run history as JSON.",
        ),
    ] = False,
) -> None:
    """List persisted audit runs from the SQLite history store."""
    try:
        with AuditStore(db_path=db_path) as store:
            records = store.list_runs(hostname=host, limit=limit)
    except Exception as e:
        typer.secho(f"Error reading audit history: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    if json_output:
        payload = [r.model_dump(mode="json") for r in records]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = Console()
    table = Table(title=f"Audit Run History ({len(records)} runs)")
    table.add_column("Run ID", style="bold cyan", no_wrap=True)
    table.add_column("Hostname", style="green")
    table.add_column("Created At (UTC)", no_wrap=True)
    table.add_column("Baseline", style="magenta")
    table.add_column("Findings", justify="right")
    table.add_column("Chains", justify="right")
    table.add_column("Degraded", justify="center")

    for r in records:
        table.add_row(
            r.run_id,
            r.hostname,
            r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            r.baseline_name,
            str(r.total_findings),
            str(r.exposure_chain_count),
            "yes" if r.degraded_mode else "no",
        )

    console.print(table)


@app.command()
def rules(
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-c",
            help="Filter rules by category (e.g. ssh, privesc, containers, kernel).",
        ),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity",
            "-s",
            help="Filter rules by default severity (critical, high, medium, low, info).",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output rules metadata as JSON.",
        ),
    ] = False,
) -> None:
    """List and inspect deterministic baseline security rules."""
    all_rules = RuleRegistry.all_rules()

    filtered = []
    for meta, _ in all_rules:
        if category and meta.category.lower() != category.lower():
            continue
        if severity and meta.default_severity.value.lower() != severity.lower():
            continue
        filtered.append(meta)

    if json_output:
        rules_data = [
            {
                "rule_id": m.rule_id,
                "title": m.title,
                "default_severity": m.default_severity.value,
                "category": m.category,
                "cis_ref": m.cis_ref,
                "mitre_attack": m.mitre_attack,
            }
            for m in filtered
        ]
        typer.echo(json.dumps(rules_data, indent=2))
        return

    console = Console()
    table = Table(title=f"Host Audit Security Rules Catalog ({len(filtered)} rules)")
    table.add_column("Rule ID", style="bold cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Title")
    table.add_column("CIS Ref", style="dim")
    table.add_column("MITRE ATT&CK", style="green")

    for m in filtered:
        sev_label = _SEV_COLORS.get(m.default_severity, m.default_severity.value)
        cis = m.cis_ref or "-"
        mitre = ", ".join(m.mitre_attack) if m.mitre_attack else "-"
        table.add_row(m.rule_id, sev_label, m.category, m.title, cis, mitre)

    console.print(table)


def _render_diff_rich(diff_result: RunDiff) -> None:
    console = Console()
    console.print(
        f"[bold]Drift Comparison:[/bold] [cyan]{diff_result.base_run_id}[/cyan] -> "
        f"[cyan]{diff_result.target_run_id}[/cyan]"
    )
    console.print(
        f"[red]NEW: {len(diff_result.new)}[/red] | "
        f"[bold red]REGRESSED: {len(diff_result.regressed)}[/bold red] | "
        f"[green]RESOLVED: {len(diff_result.resolved)}[/green] | "
        f"[yellow]PERSISTENT: {len(diff_result.persistent)}[/yellow] | "
        f"[dim]WAIVED: {len(diff_result.waived)}[/dim]\n"
    )

    buckets: list[tuple[str, str, list[Finding]]] = [
        ("NEW", "red", diff_result.new),
        ("REGRESSED", "bold red", diff_result.regressed),
        ("RESOLVED", "green", diff_result.resolved),
        ("PERSISTENT", "yellow", diff_result.persistent),
        ("WAIVED", "dim", diff_result.waived),
    ]

    for label, style, items in buckets:
        if not items:
            continue
        table = Table(title=f"{label} Findings ({len(items)})")
        table.add_column("Rule ID", style="bold cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Target", style="green")
        table.add_column("Title", style=style)
        table.add_column("Fingerprint", style="dim")
        for f in items:
            sev_label = _SEV_COLORS.get(f.severity, f.severity.value)
            table.add_row(f.rule_id, sev_label, f.target, f.title, f.fingerprint[:12])
        console.print(table)


@app.command()
def diff(
    base: Annotated[
        str | None,
        typer.Option(
            "--base",
            help="Base run_id from SQLite store.",
        ),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            help="Target run_id from SQLite store.",
        ),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option(
            "--host",
            help="Auto-compare previous vs latest run for this hostname or host_id.",
        ),
    ] = None,
    base_file: Annotated[
        Path | None,
        typer.Option(
            "--base-file",
            help="Path to offline base AuditReport JSON file.",
        ),
    ] = None,
    target_file: Annotated[
        Path | None,
        typer.Option(
            "--target-file",
            help="Path to offline target AuditReport JSON file.",
        ),
    ] = None,
    db_path: Annotated[
        Path | None,
        typer.Option(
            "--db",
            help="Override SQLite audit database path.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output RunDiff as JSON.",
        ),
    ] = False,
    fail_on_new: Annotated[
        str | None,
        typer.Option(
            "--fail-on-new",
            help="Exit 2 if any NEW or REGRESSED finding meets/exceeds severity threshold.",
        ),
    ] = None,
) -> None:
    """Compare two audit runs and report state drift."""
    if fail_on_new is not None and fail_on_new.lower() not in _FAIL_ON_WEIGHTS:
        typer.secho(
            f"Error: Invalid --fail-on-new severity '{fail_on_new}'. "
            "Must be one of: critical, high, medium, low, info.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    has_run_ids = base is not None or target is not None
    has_files = base_file is not None or target_file is not None
    has_host = host is not None

    mode_count = int(has_run_ids) + int(has_files) + int(has_host)
    if mode_count != 1:
        typer.secho(
            "Error: Specify exactly one comparison mode: "
            "(--base & --target), (--host), or (--base-file & --target-file).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        if has_files:
            if base_file is None or target_file is None:
                typer.secho(
                    "Error: Both --base-file and --target-file are required.",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            base_report = AuditReport.model_validate_json(base_file.read_text(encoding="utf-8"))
            target_report = AuditReport.model_validate_json(target_file.read_text(encoding="utf-8"))
            diff_result = diff_runs(base_report, target_report)
        else:
            with AuditStore(db_path=db_path) as store:
                if has_host and host is not None:
                    latest_runs = store.get_latest_runs_for_host(host, limit=2)
                    if len(latest_runs) < 2:
                        typer.secho(
                            f"Error: Need at least 2 runs for host '{host}' to compute diff "
                            f"(found {len(latest_runs)}).",
                            fg=typer.colors.RED,
                            err=True,
                        )
                        raise typer.Exit(code=1)
                    target_run, base_run = latest_runs[0], latest_runs[1]
                    diff_result = diff_from_store(store, base_run.run_id, target_run.run_id)
                else:
                    if base is None or target is None:
                        typer.secho(
                            "Error: Both --base and --target run IDs are required.",
                            fg=typer.colors.RED,
                            err=True,
                        )
                        raise typer.Exit(code=1)
                    diff_result = diff_from_store(store, base, target)
    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Diff error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    if json_output:
        typer.echo(diff_result.model_dump_json(indent=2))
    else:
        _render_diff_rich(diff_result)

    if fail_on_new is not None:
        threshold = _FAIL_ON_WEIGHTS[fail_on_new.lower()]
        violations = [
            f for f in [*diff_result.new, *diff_result.regressed] if f.severity.weight >= threshold
        ]
        if violations:
            raise typer.Exit(code=2)

    raise typer.Exit(code=0)


@app.command()
def export(
    format_opt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Export format: 'json', 'sarif', 'markdown', or 'ai-bundle'.",
        ),
    ],
    run_id: Annotated[
        str | None,
        typer.Argument(
            help="Run ID to load from SQLite store (omit when using --input).",
        ),
    ] = None,
    input_file: Annotated[
        Path | None,
        typer.Option(
            "--input",
            "-i",
            help="Path to an offline AuditReport JSON file.",
        ),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Output file path (writes to stdout if omitted).",
        ),
    ] = None,
    redact: Annotated[
        bool,
        typer.Option(
            "--redact",
            help="Redact hostnames, IPs, and non-root usernames (for ai-bundle).",
        ),
    ] = False,
    max_findings: Annotated[
        int,
        typer.Option(
            "--max-findings",
            help="Maximum active findings included in ai-bundle.",
        ),
    ] = 30,
    db_path: Annotated[
        Path | None,
        typer.Option(
            "--db",
            help="Override SQLite audit database path.",
        ),
    ] = None,
) -> None:
    """Export an audit report to JSON, SARIF 2.1.0, Markdown, or AI Bundle."""
    if (run_id is None and input_file is None) or (run_id is not None and input_file is not None):
        typer.secho(
            "Error: Provide either a <run_id> argument or --input <report.json> (not both).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    norm_fmt = format_opt.strip().lower()
    if norm_fmt not in (*SUPPORTED_EXPORT_FORMATS, "md"):
        typer.secho(
            f"Error: Invalid format '{format_opt}'. "
            f"Must be one of: {', '.join(SUPPORTED_EXPORT_FORMATS)}.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        snapshot = None
        if input_file is not None:
            if not input_file.is_file():
                typer.secho(
                    f"Error: Input file not found: {input_file}",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            report = AuditReport.model_validate_json(input_file.read_text(encoding="utf-8"))
        elif run_id is not None:
            with AuditStore(db_path=db_path) as store:
                loaded_report = store.get_run(run_id)
                if loaded_report is None:
                    typer.secho(
                        f"Error: Run '{run_id}' not found in audit store.",
                        fg=typer.colors.RED,
                        err=True,
                    )
                    raise typer.Exit(code=1)
                report = loaded_report
                snapshot = store.get_snapshot(run_id)

        rendered = export_report(
            report,
            norm_fmt,
            snapshot=snapshot,
            redact=redact,
            max_findings=max_findings,
        )
    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Export error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        typer.echo(f"[host-audit] Exported {norm_fmt} to {out}", err=True)
    else:
        typer.echo(rendered)


@app.command()
def triage(
    run_id: Annotated[
        str | None,
        typer.Argument(
            help="Audit run ID to triage (defaults to latest run in SQLite store).",
        ),
    ] = None,
    input_file: Annotated[
        Path | None,
        typer.Option(
            "--input",
            "-i",
            help="Path to an offline AuditReport JSON file (mutually exclusive with <run_id>).",
        ),
    ] = None,
    db_path: Annotated[
        Path | None,
        typer.Option(
            "--db",
            help="Override SQLite audit database path.",
        ),
    ] = None,
    llm_config: Annotated[
        Path | None,
        typer.Option(
            "--llm-config",
            help="Path to llm.yaml configuration file.",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            help="Override LLM model identifier (e.g., ollama/...).",
        ),
    ] = None,
    base_url: Annotated[
        str | None,
        typer.Option(
            "--base-url",
            help="Override LLM endpoint base URL.",
        ),
    ] = None,
    ssh_target: Annotated[
        str | None,
        typer.Option(
            "--ssh-target",
            help="Optional ssh://[user@]host[:port] for live read-only Stage 1 verification.",
        ),
    ] = None,
    identity: Annotated[
        Path | None,
        typer.Option(
            "--identity",
            help="SSH private key path (required when --ssh-target is set).",
        ),
    ] = None,
    accept_new_host_key: Annotated[
        bool,
        typer.Option(
            "--accept-new-host-key",
            help="Accept new SSH host keys for Stage 1 audit-ssh (default: strict).",
        ),
    ] = False,
    no_web: Annotated[
        bool,
        typer.Option(
            "--no-web",
            help="Skip Stage 2 web MCP research (pure offline/local triage).",
        ),
    ] = False,
    skills_dir: Annotated[
        Path,
        typer.Option(
            "--skills-dir",
            help="Output directory for generated remediation scripts.",
        ),
    ] = Path("./skills"),
    human_input: Annotated[
        bool,
        typer.Option(
            "--human-input/--no-human-input",
            help="Pause for human confirmation at Stage 3 remediation builder.",
        ),
    ] = True,
    dry_run_sanitizer: Annotated[
        bool,
        typer.Option(
            "--dry-run-sanitizer",
            help="Run only the deterministic sanitizer firewall and print Stage 2 JSON queries.",
        ),
    ] = False,
    no_save: Annotated[
        bool,
        typer.Option(
            "--no-save",
            help="Do not persist TriageReport into SQLite triage_runs.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Emit TriageReport JSON to stdout.",
        ),
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Write TriageReport JSON to output file.",
        ),
    ] = None,
) -> None:
    """Run local AI triage and root cause correlation (requires [crew] optional extra)."""
    if run_id is not None and input_file is not None:
        typer.secho(
            "Error: Provide either <run_id> or --input <report.json> (not both).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    # Lazy dependency check for crewai without importing at module top level
    if not dry_run_sanitizer and importlib.util.find_spec("crewai") is None:
        typer.secho(
            "Error: CrewAI optional dependencies are not installed.\n"
            'Please install them using: uv pip install "host-audit-ai[crew]"',
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        snapshot = None
        loaded_from_sqlite = False
        if input_file is not None:
            if not input_file.is_file():
                typer.secho(
                    f"Error: Input file not found: {input_file}",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            report = AuditReport.model_validate_json(input_file.read_text(encoding="utf-8"))
        else:
            with AuditStore(db_path=db_path) as store:
                if run_id is not None:
                    loaded_report = store.get_run(run_id)
                    if loaded_report is None:
                        typer.secho(
                            f"Error: Run '{run_id}' not found in audit store.",
                            fg=typer.colors.RED,
                            err=True,
                        )
                        raise typer.Exit(code=1)
                    report = loaded_report
                    snapshot = store.get_snapshot(run_id)
                else:
                    recent_runs = store.list_runs(limit=1)
                    if not recent_runs:
                        typer.secho(
                            "Error: No audit runs found in audit store. "
                            "Run 'host-audit scan' first.",
                            fg=typer.colors.RED,
                            err=True,
                        )
                        raise typer.Exit(code=1)
                    latest_id = recent_runs[0].run_id
                    loaded_latest = store.get_run(latest_id)
                    if loaded_latest is None:
                        typer.secho(
                            f"Error: Run '{latest_id}' could not be loaded.",
                            fg=typer.colors.RED,
                            err=True,
                        )
                        raise typer.Exit(code=1)
                    report = loaded_latest
                    snapshot = store.get_snapshot(latest_id)
            loaded_from_sqlite = True

        if dry_run_sanitizer:
            from host_audit_ai.crew.sanitizer import build_sanitized_queries

            sanitized_items = build_sanitized_queries(report=report, snapshot=snapshot)
            rendered_sanitized = json.dumps(
                [item.model_dump() for item in sanitized_items],
                indent=2,
            )
            if out is not None:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(rendered_sanitized, encoding="utf-8")
                typer.echo(f"[host-audit] Wrote sanitized queries to {out}", err=True)
            else:
                typer.echo(rendered_sanitized)
            return

        from host_audit_ai.crew.llm import load_llm_config
        from host_audit_ai.crew.mcp_tools import SSHServerConfig
        from host_audit_ai.crew.pipeline import TriagePipelineOptions, run_triage_pipeline

        ssh_cfg: SSHServerConfig | None = None
        if ssh_target is not None:
            if identity is None:
                typer.secho(
                    "Error: --identity <private_key> is required when --ssh-target is set.",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            ssh_cfg = SSHServerConfig(
                target=ssh_target,
                identity_file=identity,
                known_hosts_policy="accept-new" if accept_new_host_key else "strict",
            )

        llm_cfg = load_llm_config(
            config_path=llm_config,
            cli_overrides={"model": model, "base_url": base_url},
        )
        options = TriagePipelineOptions(
            llm_config=llm_cfg,
            ssh_config=ssh_cfg,
            enable_web_research=not no_web,
            skills_dir=skills_dir,
            human_input=human_input,
        )
        triage_report = run_triage_pipeline(report=report, snapshot=snapshot, options=options)

        if loaded_from_sqlite and not no_save:
            with AuditStore(db_path=db_path) as store:
                triage_id = store.save_triage(triage_report)
            typer.echo(f"[host-audit] Saved triage run: {triage_id}", err=True)

        rendered_json = triage_report.model_dump_json(indent=2)
        if out is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(rendered_json, encoding="utf-8")
            typer.echo(f"[host-audit] Wrote triage report to {out}", err=True)

        if json_output:
            typer.echo(rendered_json)
        elif out is None:
            console = Console()
            console.print(f"[bold]Triage Run:[/bold] {triage_report.run_id}")
            console.print(f"[bold]LLM Model:[/bold] {triage_report.llm_model}")
            console.print(f"\n[bold]Executive Summary:[/bold]\n{triage_report.executive_summary}")
            console.print(
                f"\nVerified evidence: {len(triage_report.verified_evidence)} | "
                f"Advisories: {len(triage_report.advisories)} | "
                f"Artifacts: {len(triage_report.artifacts)}"
            )
            if triage_report.artifacts:
                table = Table(title="Generated Remediation Artifacts (Unapproved Drafts)")
                table.add_column("Filename", style="cyan")
                table.add_column("Language")
                table.add_column("SHA-256")
                table.add_column("Summary")
                for art in triage_report.artifacts:
                    table.add_row(art.filename, art.language, art.sha256 or "", art.summary)
                console.print(table)
    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Triage error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e


@app.command(name="init-target")
def init_target(
    key_path: Annotated[
        Path,
        typer.Option(
            "--key-path",
            "-k",
            help="Path for the generated ed25519 audit SSH keypair.",
        ),
    ] = Path("~/.ssh/host_audit_ed25519"),
    wrapper_path: Annotated[
        str,
        typer.Option(
            "--wrapper-path",
            help="Target-side installation path for host-audit-wrapper.",
        ),
    ] = "/usr/local/bin/host-audit-wrapper",
    from_cidr: Annotated[
        str | None,
        typer.Option(
            "--from-cidr",
            help='Optional source IP/CIDR restriction for authorized_keys from="..." option.',
        ),
    ] = None,
    out_dir: Annotated[
        Path | None,
        typer.Option(
            "--out-dir",
            "-o",
            help="Optional directory to write host-audit-wrapper.sh and authorized_keys.entry.",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Allow overwriting an existing SSH keypair.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Emit machine-readable JSON provisioning summary.",
        ),
    ] = False,
) -> None:
    """Provision ed25519 SSH keypair and forced-command wrapper for read-only target access."""
    try:
        bundle = render_target_setup_bundle(
            key_path=key_path,
            wrapper_path=wrapper_path,
            from_cidr=from_cidr,
            force=force,
        )
    except (FileExistsError, ValueError, ProvisioningError) as e:
        typer.secho(f"Provisioning error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        wrapper_out = out_dir / "host-audit-wrapper.sh"
        entry_out = out_dir / "authorized_keys.entry"
        wrapper_out.write_text(bundle.wrapper_script, encoding="utf-8")
        wrapper_out.chmod(0o755)
        entry_out.write_text(bundle.authorized_keys_entry + "\n", encoding="utf-8")

    if json_output:
        payload = {
            "private_key_path": str(bundle.keypair.private_key_path),
            "public_key_path": str(bundle.keypair.public_key_path),
            "key_fingerprint": bundle.keypair.fingerprint,
            "wrapper_path": bundle.wrapper_path,
            "wrapper_sha256": bundle.wrapper_sha256,
            "authorized_keys_entry": bundle.authorized_keys_entry,
            "out_dir": str(out_dir) if out_dir is not None else None,
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    console = Console()
    console.print("[bold green]Generated hardened audit SSH provisioning bundle[/bold green]")
    console.print(f"- [bold]Private key:[/bold] {bundle.keypair.private_key_path} (mode 0600)")
    console.print(f"- [bold]Public key:[/bold]  {bundle.keypair.public_key_path}")
    console.print(f"- [bold]Fingerprint:[/bold] {bundle.keypair.fingerprint}")
    console.print(f"- [bold]Wrapper SHA-256:[/bold] {bundle.wrapper_sha256}")
    if out_dir is not None:
        console.print(
            f"- [bold]Exported files:[/bold] {out_dir / 'host-audit-wrapper.sh'}, "
            f"{out_dir / 'authorized_keys.entry'}"
        )
    console.print("\n[bold]authorized_keys entry:[/bold]")
    console.print(bundle.authorized_keys_entry)
    console.print(f"\n{bundle.instructions}")


if __name__ == "__main__":
    app()

"""Generate Markdown and SVG evidence artifacts from one comparison JSON file."""

from __future__ import annotations

import argparse
import html
from pathlib import Path
from typing import Any

from benchmarks.scanning.common import (
    format_bytes,
    format_duration_ns,
    format_ratio,
    read_json,
)
from benchmarks.scanning.compare import comparison_for_reporting
from benchmarks.scanning.manifest import CASES


def generate_bundle(comparison: dict[str, Any], output_dir: Path) -> None:
    comparison = comparison_for_reporting(comparison)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "charts").mkdir(exist_ok=True)
    (output_dir / "report.md").write_text(_report_markdown(comparison), encoding="utf-8")
    (output_dir / "post.md").write_text(_post_markdown(comparison), encoding="utf-8")
    _write_charts(comparison, output_dir / "charts")


def _report_markdown(comparison: dict[str, Any]) -> str:
    before = comparison["before_environment"]
    after = comparison["after_environment"]
    release_eligibility = comparison["release_eligibility"]
    comparison_status = (
        "blocking"
        if comparison["blocking"]
        else "incomplete diagnostic"
        if not comparison["complete"]
        else "diagnostic; not release eligible"
        if not release_eligibility["eligible"]
        else "accepted with performance warnings"
        if any(row["performance_regression"] for row in comparison["rows"])
        else "accepted"
    )
    lines = [
        "# Scanning performance evidence",
        "",
        f"Profile: `{comparison['profile']}`. Comparison status: `{comparison_status}`.",
        "",
        "## Methodology",
        "",
        "Historical and candidate observations were executed in separate subprocesses in randomized paired blocks. "
        "The corpus, case manifest, semantic fingerprints, Python interpreter, OS build, and target topology are "
        "recorded in the raw artifacts. Historical and candidate process cases with deterministic completion "
        "expectations perform an untimed exact-address preflight, and preflight, setup, and timed reads have "
        "independent counters. Corpus generation and correctness "
        "checks are outside timed statements. The warm PE-section row requires one untimed identical operation on "
        "the same attachment, with historical session reuse and candidate SectionCache reuse proven by raw setup "
        "and timed-read metrics. "
        "Timeout-censored historical observations are shown as lower bounds rather than fabricated completion times.",
        "",
        f"- Historical Git commit: `{_git_value(before, 'commit')}`",
        f"- Candidate Git commit: `{_git_value(after, 'commit')}`",
        f"- Python: `{after['python']['implementation']} {after['python']['version']}` "
        f"({after['python']['bitness']}-bit)",
        f"- OS: `{after['os']['system']} {after['os']['release']} {after['os']['version']}`",
        f"- CPU: `{after['cpu'].get('processor') or 'unreported'}`; "
        f"logical processors: `{after['cpu'].get('logical_count')}`",
        "- Resident/touched memory cases are memory-scanner evidence, not disk benchmarks.",
        "- Live target memory is not treated as a snapshot across separate cursor calls.",
        "",
        "## Release eligibility",
        "",
        f"Release eligible: `{'yes' if release_eligibility['eligible'] else 'no'}`.",
        "",
    ]
    if release_eligibility["reasons"]:
        lines.append("Diagnostic reasons:")
        lines.append("")
        lines.extend(f"- {reason}" for reason in release_eligibility["reasons"])
        lines.append("")
    recommendation = comparison.get("chunk_recommendation")
    if recommendation is not None:
        selected = recommendation["selected_chunk_size"]
        if selected is not None:
            prefix = "Release-eligible selection" if release_eligibility["eligible"] else "Diagnostic selection"
            selection_text = (
                f"{prefix}: `{format_bytes(selected)}` using the declared policy: {recommendation['policy']}."
            )
            if not release_eligibility["eligible"]:
                selection_text += " Diagnostic evidence does not change the production reader."
        else:
            selection_text = f"No chunk was selected: {recommendation['reason']}. Policy: {recommendation['policy']}."
        lines.extend(
            [
                "## Reader chunk selection",
                "",
                selection_text,
                "",
                "| Chunk | Throughput | Salvage p95 | Timeout overshoot p95 | Controls | Selection band |",
                "| ---: | ---: | ---: | ---: | --- | --- |",
            ]
        )
        threshold = recommendation.get("threshold_throughput_mib_s")
        for measurement in recommendation["measurements"]:
            throughput = measurement["throughput_mib_s"]
            in_band = (
                threshold is not None
                and throughput is not None
                and measurement.get("controls_valid", False)
                and throughput >= threshold
            )
            lines.append(
                f"| {format_bytes(measurement['chunk_size'])} | "
                f"{'n/a' if throughput is None else f'{throughput:.2f} MiB/s'} | "
                f"{format_duration_ns(measurement['salvage_p95_ns'])} | "
                f"{format_duration_ns(measurement['timeout_overshoot_p95_ns'])} | "
                f"{'pass' if measurement.get('controls_valid', False) else 'fail'} | "
                f"{'yes' if in_band else 'no'} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Headline matrix",
            "",
            "| Case | Class | Historical median | Candidate median | Effect | Candidate p95 | Reader use | "
            "Peak allocation before/after | Physical bytes before/after | Candidate correctness | Result |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for row in comparison["rows"]:
        if not row["headline"]:
            continue
        lines.append(
            "| `{case}` | {classification} | {before} | {after} | {effect} | {p95} | {reader} | "
            "{allocation} | {reads} | {correctness} | {result} |".format(
                case=row["case_id"],
                classification=row["comparison_class"].replace("_", " "),
                before=_duration_cell(row["before"]),
                after=_duration_cell(row["after"]),
                effect=_effect_cell(row),
                p95=format_duration_ns(row["after"]["duration_ns"]["p95"]),
                reader=_percent(row.get("reader_utilization")),
                allocation=(
                    f"{format_bytes(row['before']['peak_python_bytes']['median'])} / "
                    f"{format_bytes(row['after']['peak_python_bytes']['median'])}"
                ),
                reads=(
                    f"{format_bytes(row['before']['physical_bytes_read']['median'])} / "
                    f"{format_bytes(row['after']['physical_bytes_read']['median'])}"
                ),
                correctness=_correctness_cell(row["after"]),
                result=(
                    "blocking"
                    if row["blocking"]
                    else "performance warning"
                    if row["performance_regression"]
                    else row["status"]
                ),
            )
        )

    lines.extend(["", "## Detailed groups", ""])
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in comparison["rows"]:
        groups.setdefault(row["group"], []).append(row)
    for group, rows in groups.items():
        lines.extend(
            [
                f"### {group}",
                "",
                "| Case | Historical throughput | Candidate throughput | Peak Python allocation before/after | "
                "Physical bytes before/after | Notes |",
                "| --- | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for row in rows:
            allocation = (
                f"{format_bytes(row['before']['peak_python_bytes']['median'])} / "
                f"{format_bytes(row['after']['peak_python_bytes']['median'])}"
            )
            reads = (
                f"{format_bytes(row['before']['physical_bytes_read']['median'])} / "
                f"{format_bytes(row['after']['physical_bytes_read']['median'])}"
            )
            lines.append(
                f"| `{row['case_id']}` | {_throughput(row['before'])} | {_throughput(row['after'])} | "
                f"{allocation} | {reads} | {_notes(row)} |"
            )
        lines.append("")

    selected_case_ids = comparison["before_environment"]["runner"]["case_ids"]
    full_manifest_case_ids = [case.case_id for case in CASES]
    coverage_text = (
        "Every manifest case remains visible. Missing, invalid, censored, neutral, and regressing rows are not "
        "removed from this appendix."
        if selected_case_ids == full_manifest_case_ids
        else "Every selected case remains visible. Unselected manifest cases are outside this diagnostic subset; "
        "missing, invalid, censored, neutral, and regressing selected rows are not removed."
    )
    lines.extend(
        [
            "## Coverage appendix",
            "",
            coverage_text,
            "",
            "| Case | Tier | Layer | Status | Before observations | After observations | Correct after | Blocking |",
            "| --- | --- | --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for row in comparison["rows"]:
        lines.append(
            f"| `{row['case_id']}` | {row['tier']} | {row['layer']} | {row['status']} | "
            f"{row['before']['observation_count']} | {row['after']['observation_count']} | "
            f"{row['after']['correct_count']} | {'yes' if row['blocking'] else 'no'} |"
        )

    lines.extend(
        [
            "",
            "## Artifact traceability",
            "",
            "The complete observations and environment metadata are in `raw-before.json` and `raw-after.json`. "
            "Machine-readable deltas are in `comparison.json` and `comparison.csv`. Every row, chart label, and "
            "claim uses the stable `case_id` shown above.",
            "",
            "Generated charts:",
            "",
            "- `charts/matcher-throughput.svg`",
            "- `charts/end-to-end-throughput.svg`",
            "- `charts/latency-speedup.svg`",
            "- `charts/allocation.svg`",
            "- `charts/read-reduction.svg`",
            "",
        ]
    )
    return "\n".join(lines)


def _post_markdown(comparison: dict[str, Any]) -> str:
    accepted = [
        row
        for row in comparison["rows"]
        if not row["blocking"]
        and (row["paired_speedup"]["median"] is not None or row["censored_speedup_lower_bound"] is not None)
    ]
    strongest = sorted(
        accepted,
        key=lambda row: row["paired_speedup"]["median"] or row["censored_speedup_lower_bound"] or 0,
        reverse=True,
    )[:4]
    lines = [
        "# Scanning performance update",
        "",
        "The scanning subsystem now uses one bounded engine for MCP and Lua AOB, string, pointer, continuation, "
        "and first/count batch operations. The comparison below is same-machine evidence over a fixed manifest, "
        "not a universal hardware claim.",
        "",
    ]
    if comparison["blocking"]:
        lines.append(
            "The current evidence bundle contains blocking rows, is not release eligible, and is not suitable "
            "for release claims. See `report.md` and `comparison.json` for the exact case IDs."
        )
    elif not comparison["complete"]:
        lines.append(
            "This is a partial diagnostic bundle and is not release eligible. Missing cases remain visible in "
            "`report.md`; no release-wide claim should be made from this subset."
        )
    elif not comparison["release_eligibility"]["eligible"]:
        reasons = "; ".join(comparison["release_eligibility"]["reasons"])
        lines.append(f"This bundle is diagnostic and not release eligible: {reasons}.")
    elif strongest:
        lines.append("Representative fixed cases:")
        lines.append("")
        for row in strongest:
            lines.append(f"- `{row['case_id']}`: {_effect_cell(row)}.")
        lines.extend(
            [
                "",
                "The full report also includes neutral results, censored historical runs, reader-ceiling context, "
                "allocation, read amplification, cursor, batch, timeout, and strict-boundary evidence.",
            ]
        )
    else:
        lines.append("The bundle contains correctness and capability evidence but no valid paired speedup claims.")
    lines.append("")
    return "\n".join(lines)


def _write_charts(comparison: dict[str, Any], chart_dir: Path) -> None:
    matcher_rows = [row for row in comparison["rows"] if row["group"] == "Matcher CPU"]
    e2e_rows = [row for row in comparison["rows"] if row["group"] == "Contiguous end-to-end"]
    _bar_chart(
        chart_dir / "matcher-throughput.svg",
        "Matcher throughput (MiB/s)",
        [(row["case_id"], row["after"]["throughput_mib_s"]["median"] or 0) for row in matcher_rows],
    )
    _bar_chart(
        chart_dir / "end-to-end-throughput.svg",
        "End-to-end throughput (MiB/s)",
        [(row["case_id"], row["after"]["throughput_mib_s"]["median"] or 0) for row in e2e_rows],
    )
    _bar_chart(
        chart_dir / "latency-speedup.svg",
        "Paired latency speedup",
        [
            (
                row["case_id"],
                row["paired_speedup"]["median"] or row["censored_speedup_lower_bound"] or 0,
            )
            for row in comparison["rows"]
            if row["paired_speedup"]["median"] is not None or row["censored_speedup_lower_bound"] is not None
        ],
    )
    _bar_chart(
        chart_dir / "allocation.svg",
        "Candidate peak Python allocation (MiB)",
        [
            (row["case_id"], (row["after"]["peak_python_bytes"]["median"] or 0) / (1024 * 1024))
            for row in comparison["rows"]
            if row["after"]["peak_python_bytes"]["median"] is not None
        ],
    )
    _bar_chart(
        chart_dir / "read-reduction.svg",
        "Physical read reduction (%)",
        [
            (row["case_id"], max(-100.0, min(100.0, (row["read_reduction_fraction"] or 0) * 100)))
            for row in comparison["rows"]
            if row["read_reduction_fraction"] is not None
        ],
    )


def _bar_chart(path: Path, title: str, items: list[tuple[str, float]]) -> None:
    items = items[:24]
    width = 1100
    row_height = 30
    label_width = 390
    chart_width = 620
    height = 70 + max(1, len(items)) * row_height
    maximum = max((abs(value) for _label, value in items), default=1) or 1
    rows: list[str] = []
    for index, (label, value) in enumerate(items):
        y = 58 + index * row_height
        bar_width = abs(value) / maximum * chart_width
        rows.append(
            f'<text x="10" y="{y + 16}" font-size="12">{html.escape(label)}</text>'
            f'<rect x="{label_width}" y="{y}" width="{bar_width:.2f}" height="18" fill="currentColor" opacity="0.55"/>'
            f'<text x="{label_width + bar_width + 8:.2f}" y="{y + 15}" font-size="12">{value:.2f}</text>'
        )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">'
        "<style>text{font-family:system-ui,sans-serif;fill:currentColor}</style>"
        f'<text x="10" y="28" font-size="20" font-weight="600">{html.escape(title)}</text>' + "".join(rows) + "</svg>\n"
    )
    path.write_text(svg, encoding="utf-8")


def _git_value(environment: dict[str, Any], field: str) -> str:
    return str(environment.get("git", {}).get(field) or "unavailable")


def _duration_cell(summary: dict[str, Any]) -> str:
    return format_duration_ns(summary["duration_ns"]["median"])


def _throughput(summary: dict[str, Any]) -> str:
    value = summary["throughput_mib_s"]["median"]
    return "n/a" if value is None else f"{value:.2f} MiB/s"


def _effect_cell(row: dict[str, Any]) -> str:
    if row["paired_speedup"]["median"] is not None:
        interval = row["paired_speedup"]
        return (
            f"{format_ratio(interval['median'])} "
            f"(95% bootstrap {format_ratio(interval['ci_low'])}-{format_ratio(interval['ci_high'])})"
        )
    if row["censored_speedup_lower_bound"] is not None:
        return f">{format_ratio(row['censored_speedup_lower_bound'])}"
    if row["read_reduction_fraction"] is not None:
        return f"{row['read_reduction_fraction'] * 100:.1f}% fewer physical bytes"
    if row["allocation_reduction_fraction"] is not None:
        return f"{row['allocation_reduction_fraction'] * 100:.1f}% lower allocation"
    return "n/a"


def _percent(value: float | int | None) -> str:
    return "n/a" if value is None else f"{float(value) * 100:.1f}%"


def _correctness_cell(summary: dict[str, Any]) -> str:
    text = f"{summary['correct_count']}/{summary['observation_count']}"
    checksum = summary.get("expected_checksum")
    if checksum:
        text += f"; checksum `{checksum}`"
    return text


def _notes(row: dict[str, Any]) -> str:
    return "; ".join(row["notes"]) if row["notes"] else "-"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparison", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    generate_bundle(read_json(arguments.comparison), arguments.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

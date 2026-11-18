"""Regenerate the README benchmark chart from the published report tables."""

import re
from decimal import Decimal
from pathlib import Path

DOCS = Path(__file__).resolve().parent
RESULTS = DOCS.parent / "evals" / "results"
METRICS = ("Precision", "Recall", "F1", "FPR")


def read_metrics(report: Path, row_label: str) -> tuple[str, ...]:
    metric = r"[ \t]*(0\.[0-9]{4}|1\.0000)[ \t]*\|"
    row = re.search(
        rf"^\| {re.escape(row_label)} \|{metric * len(METRICS)}",
        report.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if row is None:
        raise ValueError(f"{report}: missing or invalid benchmark row {row_label!r}")
    return row.groups()


def benchmark_svg() -> str:
    series = (
        (
            "v0.1.0",
            "#64748b",
            read_metrics(
                RESULTS / "benchmark-v0.1.0-core.md",
                "Rules + classifier (threshold 0.5)",
            ),
        ),
        (
            "v0.2.0",
            "#087f75",
            read_metrics(RESULTS / "benchmark-v0.2.0.md", "v0.2.0"),
        ),
        (
            "v0.3.0",
            "#7544ba",
            read_metrics(RESULTS / "benchmark-v0.3.0.md", "v0.3.0"),
        ),
    )
    plot_left, plot_right = 64, 764
    plot_bottom, plot_height = 332, 200
    group_width = (plot_right - plot_left) / len(METRICS)
    bar_width, gap = 42, 9
    series_width = len(series) * bar_width + (len(series) - 1) * gap
    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="388"',
        '     viewBox="0 0 800 388"',
        '     role="img" aria-labelledby="chart-title chart-description">',
        '  <title id="chart-title">AgentSentinel independent benchmark</title>',
        '  <desc id="chart-description">Grouped bars compare v0.1.0, v0.2.0,',
        "    and v0.3.0 on the 120-trace corpus at threshold 0.5.",
        "    FPR is the false-positive rate.</desc>",
        "  <style>",
        "    text { font-family: system-ui, sans-serif; fill: #17283d; }",
        "    .heading { font-size: 26px; font-weight: 700; }",
        "    .subtitle, .tick { fill: #475569; }",
        "    .subtitle, .legend, .metric, .value { font-size: 14px; }",
        "    .metric, .value { font-weight: 600; }",
        "    .tick { font-size: 12px; }",
        "    .tick, .value { font-variant-numeric: tabular-nums; }",
        "    .bar:hover rect, .bar:focus rect { stroke: #17283d; stroke-width: 2; }",
        "  </style>",
        '  <rect x="0.5" y="0.5" width="799" height="387" rx="16"',
        '        fill="#f8fafc" stroke="#cbd5e1"/>',
        '  <text x="36" y="46" class="heading">Independent benchmark</text>',
        '  <text x="36" y="71" class="subtitle">',
        "    120 traces · default threshold 0.5",
        "  </text>",
    ]
    for index, (version, color, _) in enumerate(series):
        legend_x = 36 + index * 110
        svg.extend(
            [
                f'  <rect x="{legend_x}" y="92" width="13" height="13" rx="2" '
                f'fill="{color}"/>',
                f'  <text x="{legend_x + 21}" y="103" class="legend">{version}</text>',
            ]
        )
    for tick in range(6):
        rate = tick / 5
        tick_y = plot_bottom - rate * plot_height
        svg.extend(
            [
                f'  <path d="M{plot_left} {tick_y:g} H{plot_right}" stroke="#cbd5e1"/>',
                f'  <text x="{plot_left - 10}" y="{tick_y + 4:g}" text-anchor="end" '
                f'class="tick">{rate:.1f}</text>',
            ]
        )
    for metric_index, metric in enumerate(METRICS):
        center = plot_left + (metric_index + 0.5) * group_width
        svg.append(
            f'  <text x="{center:g}" y="362" text-anchor="middle" '
            f'class="metric">{metric}</text>'
        )
        for index, (version, color, values) in enumerate(series):
            x = center - series_width / 2 + index * (bar_width + gap)
            value = values[metric_index]
            height = Decimal(value) * plot_height
            y = plot_bottom - height
            label = f"{version} {metric} {value}"
            svg.extend(
                [
                    f'  <g class="bar" tabindex="0" role="img" aria-label="{label}">',
                    f"    <title>{label}</title>",
                    f'    <rect x="{x:g}" y="{y:.3f}" width="{bar_width}" '
                    f'height="{height:.3f}" fill="{color}"/>',
                    f'    <text x="{x + bar_width / 2:g}" y="{y - 8:.3f}" '
                    f'text-anchor="middle" class="value">{value}</text>',
                    "  </g>",
                ]
            )
    return "\n".join([*svg, "</svg>", ""])


def main() -> None:
    svg = benchmark_svg()
    output = DOCS / "assets" / "benchmark.svg"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(svg, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()

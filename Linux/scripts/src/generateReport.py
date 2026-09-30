#!/usr/bin/env python3
"""Generate the DNS Detection and Analytics report as a PDF.

Usage: python generateReport.py [-o report.pdf] [--days N]
"""
import os
import sys
import sqlite3
import argparse
from collections import Counter
from datetime import datetime, timedelta

import matplotlib
matplotlib.use("Agg")  # no display needed, works on headless servers
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.patches import Rectangle

script_path = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(script_path, "networkdata.db")

# Query packets carry no response code; responses do.
IS_QUERY = "coalesce(rcode, '') = ''"
# On a query the client is the source, on a response it is the destination.
CLIENT = "case when {} then src else dst end".format(IS_QUERY)

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
RCODES = {0: "No Error", 1: "Format Error", 2: "Server Failure",
          3: "Non Existent Domain", 5: "Refused"}

# AttackFence brand, read straight off the live site's CSS custom properties
# (--color-black, --color-primary, --color-hover, --color-white, --color-heading)
# and sampled from the official wordmark. The report is dark by design: the
# brand's own surface is near-black, so a white page would not be AttackFence.
PAGE_BG = "#160001"   # --color-black, the exact backdrop of the AttackFence site
PANEL = "#210a0c"     # one step up, for table bands and stat tiles
BRAND = "#e51f28"     # --color-primary
BRAND_DIM = "#b71920"  # --color-hover
INK, INK2 = "#ffffff", "#c0c0c0"   # --color-white, --color-heading (silver)
MUTED, GRID, RULE = "#8a7f80", "#332021", "#3d2628"  # sampled from the wordmark

# Categorical slots, in fixed order. Validated on the #160001 surface: both sit
# in the dark lightness band, clear the chroma floor, and separate by dE 15.0
# under deuteranopia (>= 8) and 33.5 unsimulated (>= 15).
SERIES = [BRAND, "#12a09d"]
# Reserved status colours - never reused as a series hue, always paired with the
# verdict's own label so the meaning never rests on colour alone.
VERDICT_COLORS = {"malicious": "#d03b3b", "is_malicious": "#d03b3b",
                  "suspicious": "#ec835a", "is_suspicious": "#ec835a",
                  "benign": "#0ca30c"}
PAGE = (11.69, 8.27)  # A4 landscape

BRAND_DIR = os.path.join(script_path, "brand")
WORDMARK = os.path.join(BRAND_DIR, "af_wordmark.png")


def use_brand_font():
    """ Inter is the AttackFence web face; bundled so the sensor needs no network.
        A missing font must never stop a report being produced, so this is soft. """
    try:
        import matplotlib.font_manager as fm
        faces = [os.path.join(BRAND_DIR, f)
                 for f in ("Inter-400.ttf", "Inter-600.ttf", "Inter-700.ttf")]
        faces = [f for f in faces if os.path.exists(f)]
        for face in faces:
            fm.fontManager.addfont(face)
        if faces:
            plt.rcParams["font.family"] = "Inter"
    except Exception as exc:
        print("brand font unavailable, falling back to the default face: {}".format(exc))


use_brand_font()
plt.rcParams.update({
    "figure.facecolor": PAGE_BG, "axes.facecolor": PAGE_BG, "savefig.facecolor": PAGE_BG,
    "text.color": INK, "axes.labelcolor": INK2,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.edgecolor": RULE,
})


def new_page(title, subtitle, number):
    fig = plt.figure(figsize=PAGE)
    fig.text(0.05, 0.925, title, fontsize=17, fontweight="bold", color=INK)
    fig.text(0.05, 0.888, subtitle, fontsize=9, color=INK2)
    # The brand rule: a short solid bar in AttackFence red under the page title
    fig.add_artist(Rectangle((0.05, 0.872), 0.055, 0.005, figure=fig,
                             facecolor=BRAND, edgecolor="none"))
    fig.add_artist(Rectangle((0.105, 0.8735), 0.845, 0.0008, figure=fig,
                             facecolor=RULE, edgecolor="none"))
    if os.path.exists(WORDMARK):
        logo = plt.imread(WORDMARK)
        width = 0.15
        height = width * PAGE[0] * logo.shape[0] / (logo.shape[1] * PAGE[1])
        ax = fig.add_axes([0.95 - width, 0.925, width, height])
        ax.imshow(logo, interpolation="antialiased")
        ax.axis("off")
    fig.text(0.05, 0.03, "AttackFence  |  Donatix DNS Detection and Analytics",
             fontsize=8, color=MUTED)
    fig.text(0.95, 0.03, "Page {}".format(number), fontsize=8, color=MUTED, ha="right")
    return fig


def grid(fig):
    axs = fig.subplots(2, 2)
    fig.subplots_adjust(left=0.2, right=0.95, top=0.82, bottom=0.09, wspace=0.8, hspace=0.4)
    return axs.ravel()


def empty(ax, title, message):
    ax.set_title(title, fontsize=11, color=INK, loc="left", fontweight="bold", pad=10)
    ax.axis("off")
    ax.text(0.5, 0.5, message, ha="center", va="center", fontsize=9, color=MUTED,
            transform=ax.transAxes)


def hbar(ax, data, title, colors=BRAND):
    """ Horizontal bar chart of (label, value) pairs, largest first """
    if not data:
        return empty(ax, title, "No data")
    ax.set_title(title, fontsize=11, color=INK, loc="left", fontweight="bold", pad=10)
    positions = [9 - i for i in range(len(data))]  # ten slots, so bars keep one thickness
    bars = ax.barh(positions, [value for _, value in data], height=0.55, color=colors)
    ax.bar_label(bars, labels=["{:,}".format(value) for _, value in data],
                 padding=4, fontsize=8, color=INK2)
    ax.set_ylim(-0.5, 9.5)
    ax.set_yticks(positions)
    # tshark only records IPv4 addresses, so IPv6 packets have a blank address
    ax.set_yticklabels([str(label)[:32] or "(unknown)" for label, _ in data], fontsize=8, color=INK2)
    ax.tick_params(length=0)
    ax.xaxis.set_visible(False)
    ax.margins(x=0.15)
    for side in ("top", "right", "bottom"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color(RULE)


def table(ax, title, columns, data, limit=10, loc="upper right"):
    if not data:
        return empty(ax, title, "None detected")
    if len(data) > limit:
        title = "{} (top {} of {})".format(title, limit, len(data))
    ax.set_title(title, fontsize=11, color=INK, loc="left", fontweight="bold", pad=10)
    ax.axis("off")
    cells = [[str(value)[:38] for value in row] for row in data[:limit]]
    tbl = ax.table(cellText=cells, colLabels=columns, loc=loc, cellLoc="left")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8)
    tbl.scale(1, 1.4)
    tbl.auto_set_column_width(range(len(columns)))
    for (row, _), cell in tbl.get_celld().items():
        cell.set_linewidth(0.6)
        if row == 0:
            # Header sits on a red-tinted band, the only chrome that carries the brand
            cell.set_facecolor("#2d0c0f")
            cell.set_edgecolor(BRAND_DIM)
            cell.get_text().set_color(INK)
            cell.get_text().set_fontweight("bold")
        else:
            # Alternating bands, so a long table stays readable on a dark page
            cell.set_facecolor(PANEL if row % 2 else PAGE_BG)
            cell.set_edgecolor(GRID)
            cell.get_text().set_color(INK2)


def optional(conn, sql):
    """ Rows of a table that only exists once its detection service has run """
    try:
        return conn.execute(sql).fetchall()
    except sqlite3.OperationalError:
        return []


def generate_report(output, days=None):
    if not os.path.exists(db_path):
        sys.exit("Database not found: {}".format(db_path))
    conn = sqlite3.connect(db_path)
    since = str(datetime.now() - timedelta(days=days)) if days else ""

    def query(sql):
        return conn.execute(sql.format(Q=IS_QUERY, C=CLIENT), (since,)).fetchall()

    total, queries, clients, first, last = query("""
        select count(*), sum({Q}), count(distinct case when {Q} then src end),
        min(time), max(time) from dns_query_data where time >= ?""")[0]
    if not total:
        sys.exit("No DNS data captured for the requested period")
    subtitle = "{} to {}   |   generated {:%Y-%m-%d %H:%M}".format(first[:19], last[:19], datetime.now())

    # Bucket the timeline by minute, hour or day depending on the period covered
    span = datetime.strptime(last[:19], "%Y-%m-%d %H:%M:%S") - datetime.strptime(first[:19], "%Y-%m-%d %H:%M:%S")
    buckets = [16 if span < timedelta(hours=3) else 13 if span < timedelta(days=3) else 10]
    # A stored sample batch leaves the span huge while the traffic itself sits in a
    # day or two, which collapses the line to a couple of points. Step to a finer
    # bucket when the span-appropriate one has too little to draw a line from.
    buckets += [size for size in (13, 16) if size > buckets[0]]
    for bucket in buckets:
        timeline = query("select substr(time, 1, %d), sum({Q}), count(*) - sum({Q}) "
                         "from dns_query_data where time >= ? group by 1 order by 1" % bucket)
        if len(timeline) >= 8:
            break

    domains = query("select qname, count(*) from dns_query_data where {Q} and qname != '' "
                    "and time >= ? group by 1 order by 2 desc")
    tlds = Counter()
    for qname, count in domains:
        tlds[qname.rstrip(".").rsplit(".", 1)[-1].lower()] += count
    query_types = [(QTYPES.get(qtype, "Other"), count) for qtype, count in query(
        "select qtype, count(*) from dns_query_data where {Q} and time >= ? group by 1 order by 2 desc")]
    response_codes = [(RCODES.get(rcode, "Code {}".format(rcode)), count) for rcode, count in query(
        "select rcode, count(*) from dns_query_data where not {Q} and time >= ? group by 1 order by 2 desc")]
    servers = query("select dst, count(*) from dns_query_data where {Q} and time >= ? "
                    "group by 1 order by 2 desc limit 10")
    hosts = query("select src, count(*), count(distinct qname) from dns_query_data where {Q} "
                  "and time >= ? group by 1 order by 2 desc limit 10")
    stats = []
    for name, column in (("Query name length", "qlen"), ("Label count", "labelcount"), ("TTL (seconds)", "ttl")):
        stats.append((name,) + query("select round(avg({0}), 1), max({0}), min({0}) from dns_query_data "
                                     "where typeof({0}) = 'integer' and time >= ?".format(column))[0])

    verdicts = query("select coalesce(nullif(tiVerdict, ''), 'not checked'), count(*) "
                     "from dns_query_data where time >= ? group by 1 order by 2 desc")
    # The verdict belongs to the answer's address when there is one, otherwise to the queried name
    flagged = query("""select qname, case when dnsResponse != '' then dnsResponse else qname end, tiVerdict,
                       count(distinct {C}), count(*) from dns_query_data
                       where lower(tiVerdict) in ('malicious', 'suspicious', 'is_malicious', 'is_suspicious')
                       and time >= ? group by 1, 2, 3 order by 5 desc""")
    dga_domains = query("select qname, count(distinct src), count(*) from dns_query_data "
                        "where isDGA = 1 and {Q} and time >= ? group by 1 order by 3 desc")
    dga_hosts = query("select src, count(*) from dns_query_data where isDGA = 1 and {Q} "
                      "and time >= ? group by 1 order by 2 desc limit 10")
    beaconing = optional(conn, "select distinct srcIp, destIp, numQueries, numResponses, "
                               "responsePercentage from beaconingHosts")
    tunneling = optional(conn, "select qname, max(queryCount) from dnsTunneling group by 1 order by 2 desc")
    conn.close()

    with PdfPages(output) as pdf:
        # Page 1: headline numbers and traffic over time
        fig = new_page("AttackFence Donatix DNS Threat Report", subtitle, 1)
        headline = [("DNS queries", queries), ("DNS responses", total - queries),
                    ("Hosts", clients), ("Domains queried", len(domains)),
                    ("DGA domains", len(dga_domains)), ("Malicious / suspicious", len(flagged))]
        for i, (label, value) in enumerate(headline):
            x = 0.05 + i * 0.155
            # A red keyline above each figure, echoing the rule under the title
            fig.add_artist(Rectangle((x, 0.822), 0.022, 0.004, figure=fig,
                                     facecolor=BRAND, edgecolor="none"))
            fig.text(x, 0.772, "{:,}".format(value), fontsize=23, fontweight="bold", color=INK)
            fig.text(x, 0.737, label, fontsize=9, color=INK2)
        ax = fig.add_axes([0.07, 0.14, 0.88, 0.5])
        ax.set_title("Queries and responses over time", fontsize=11, color=INK,
                     loc="left", fontweight="bold", pad=10)
        labels = [row[0] for row in timeline]
        marker = "o" if len(labels) < 30 else None
        ax.plot(labels, [row[1] for row in timeline], color=SERIES[0], linewidth=2,
                marker=marker, markersize=4.5, label="Queries")
        ax.plot(labels, [row[2] for row in timeline], color=SERIES[1], linewidth=2,
                linestyle=(0, (5, 2)), marker=marker, markersize=4.5, label="Responses")
        ax.set_ylim(bottom=0)
        ax.set_xticks(range(0, len(labels), len(labels) // 7 + 1))
        ax.tick_params(length=0, labelsize=8, labelcolor=MUTED)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        legend = ax.legend(frameon=False, fontsize=9, ncol=2, loc="lower right",
                           bbox_to_anchor=(1, 1))
        for text in legend.get_texts():
            text.set_color(INK2)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(RULE)
        pdf.savefig(fig, facecolor=PAGE_BG)
        plt.close(fig)

        # Page 2: what is being asked and how it is answered
        fig = new_page("Traffic Breakdown", subtitle, 2)
        axs = grid(fig)
        hbar(axs[0], query_types[:8], "Query types")
        hbar(axs[1], response_codes[:8], "Response codes")
        hbar(axs[2], tlds.most_common(10), "Top level domains by queries")
        hbar(axs[3], servers, "DNS servers by queries")
        pdf.savefig(fig, facecolor=PAGE_BG)
        plt.close(fig)

        # Page 3: who is asking for what
        fig = new_page("Hosts and Domains", subtitle, 3)
        axs = grid(fig)
        hbar(axs[0], domains[:10], "Top domains by queries")
        hbar(axs[1], [(src, count) for src, count, _ in hosts], "Queries by host")
        hbar(axs[2], sorted(((src, names) for src, _, names in hosts), key=lambda row: -row[1]),
             "Distinct domains visited by host")
        table(axs[3], "Query name length, label count and TTL", ["Metric", "Average", "Maximum", "Minimum"], stats)
        pdf.savefig(fig, facecolor=PAGE_BG)
        plt.close(fig)

        # Page 4: threat intel and DGA detections
        fig = new_page("Threat Intelligence and DGA Detection", subtitle, 4)
        axs = grid(fig)
        checked = [row for row in verdicts if row[0] != "not checked"]
        unchecked = sum(count for verdict, count in verdicts if verdict == "not checked")
        hbar(axs[0], checked,
             "Threat intel verdicts  |  {:,} not checked".format(unchecked),
             colors=[VERDICT_COLORS.get(str(verdict).lower(), MUTED) for verdict, _ in checked])
        table(axs[1], "Flagged indicators", ["Domain", "Indicator", "Verdict", "Hosts", "Packets"], flagged)
        hbar(axs[2], dga_hosts, "DGA queries by host")
        table(axs[3], "DGA domains", ["Domain", "Hosts", "Queries"], dga_domains)
        pdf.savefig(fig, facecolor=PAGE_BG)
        plt.close(fig)

        # Page 5: beaconing and tunneling detections
        fig = new_page("Beaconing and DNS Tunneling Detection", subtitle, 5)
        axs = fig.subplots(1, 2)
        fig.subplots_adjust(left=0.05, right=0.95, top=0.82, bottom=0.09, wspace=0.15)
        table(axs[0], "Beaconing hosts", ["Source", "Destination", "Requests", "Responses", "Response %"],
              beaconing, limit=20, loc="upper left")
        table(axs[1], "DNS tunneling domains", ["Domain", "Queries"], tunneling, limit=20, loc="upper left")
        pdf.savefig(fig, facecolor=PAGE_BG)
        plt.close(fig)
    print("Report written to {}".format(os.path.abspath(output)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate the DNS analytics report as a PDF")
    parser.add_argument("-o", "--output", default="Donatix_Report_{:%Y-%m-%d}.pdf".format(datetime.now()))
    parser.add_argument("--days", type=int, help="only report on the last N days (default: all data)")
    args = parser.parse_args()
    generate_report(args.output, args.days)

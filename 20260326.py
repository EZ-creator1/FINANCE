#!/usr/bin/env python3

import argparse
import os
import pwd
import re
import subprocess
import sys
import time
from pathlib import Path


HEADER_RE = re.compile(
    r"^\S+\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+users:\(\(\"([^\"]+)\",pid=(\d+),fd=\d+\)\))?$"
)
BYTES_SENT_RE = re.compile(r"bytes_sent:(\d+)")
BYTES_RECV_RE = re.compile(r"bytes_received:(\d+)")


def format_bytes(value: float) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TiB"


def run_ss() -> str:
    cmd = ["ss", "-tinpH"]
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        raise SystemExit("未找到 ss 命令，无法采集套接字统计。")
    except subprocess.CalledProcessError as exc:
        message = exc.output.strip() or str(exc)
        raise SystemExit(f"执行 {' '.join(cmd)} 失败: {message}")


def pid_uid(pid: int):
    try:
        return os.stat(f"/proc/{pid}").st_uid
    except (FileNotFoundError, PermissionError):
        return None


def parse_ss_output(text: str, target_uid: int):
    per_pid = {}
    current = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue

        if not raw_line.startswith((" ", "\t")):
            match = HEADER_RE.match(line)
            current = None
            if not match:
                continue
            local_addr, peer_addr, proc_name, pid_text = match.groups()
            if not pid_text:
                continue
            pid = int(pid_text)
            if pid_uid(pid) != target_uid:
                continue
            current = {
                "pid": pid,
                "proc": proc_name or "?",
                "local": local_addr,
                "peer": peer_addr,
            }
            continue

        if current is None:
            continue

        sent_match = BYTES_SENT_RE.search(line)
        recv_match = BYTES_RECV_RE.search(line)
        if not sent_match or not recv_match:
            continue

        pid = current["pid"]
        entry = per_pid.setdefault(
            pid,
            {
                "proc": current["proc"],
                "sent": 0,
                "recv": 0,
                "connections": 0,
                "peers": set(),
            },
        )
        entry["sent"] += int(sent_match.group(1))
        entry["recv"] += int(recv_match.group(1))
        entry["connections"] += 1
        entry["peers"].add(f"{current['local']} -> {current['peer']}")
        current = None

    return per_pid


def sample_user_traffic(target_uid: int):
    return parse_ss_output(run_ss(), target_uid)


def diff_samples(first, second, interval: float):
    rows = []
    all_pids = set(first) | set(second)
    for pid in all_pids:
        before = first.get(pid, {})
        after = second.get(pid, {})
        proc = after.get("proc") or before.get("proc") or "?"
        sent_before = int(before.get("sent", 0))
        recv_before = int(before.get("recv", 0))
        sent_after = int(after.get("sent", 0))
        recv_after = int(after.get("recv", 0))
        delta_sent = max(0, sent_after - sent_before)
        delta_recv = max(0, recv_after - recv_before)
        rows.append(
            {
                "pid": pid,
                "proc": proc,
                "connections": int(after.get("connections", before.get("connections", 0))),
                "sent_total": sent_after,
                "recv_total": recv_after,
                "sent_rate": delta_sent / interval,
                "recv_rate": delta_recv / interval,
                "peers": sorted(after.get("peers", before.get("peers", set()))),
            }
        )

    rows.sort(key=lambda item: item["sent_rate"] + item["recv_rate"], reverse=True)
    return rows


def print_table(rows, limit: int):
    print(
        f"{'PID':>8}  {'PROC':<22} {'CONN':>4}  {'TX/s':>10}  {'RX/s':>10}  {'TX_TOTAL':>10}  {'RX_TOTAL':>10}"
    )
    print("-" * 86)
    for row in rows[:limit]:
        print(
            f"{row['pid']:>8}  {str(row['proc'])[:22]:<22} {row['connections']:>4}  "
            f"{format_bytes(row['sent_rate']):>10}  {format_bytes(row['recv_rate']):>10}  "
            f"{format_bytes(row['sent_total']):>10}  {format_bytes(row['recv_total']):>10}"
        )
        for peer in row["peers"][:3]:
            print(f"          peer {peer}")


def historical_sources():
    sources = []
    if list(Path("/var/log").glob("sa*/sa*")) or list(Path("/var/log/sysstat").glob("sa*")):
        sources.append("发现 sysstat/sar 历史文件，可查系统级网络历史，但通常不是进程级流量。")
    if Path("/var/log/atop").exists():
        sources.append("发现 atop 历史目录；若历史采集时启用了网络字段，可能能追到部分进程视角。")
    if Path("/var/lib/vnstat").exists():
        sources.append("发现 vnStat 数据库；它提供接口级历史，不提供进程级历史。")
    return sources


def print_history_summary():
    sources = historical_sources()
    if not sources:
        print("未发现可直接读取的历史流量采样源。")
        print("这台机器目前大概率无法回溯“历史进程流量”；进程级历史必须提前由 atop、eBPF、nethogs 等工具持续采集。")
        return 1

    print("发现以下历史流量来源:")
    for line in sources:
        print(f"- {line}")
    return 0


def parse_args():
    parser = argparse.ArgumentParser(description="按当前用户聚合进程网络流量，并检查历史采样源。")
    parser.add_argument("--user", default=pwd.getpwuid(os.getuid()).pw_name, help="目标用户名，默认当前用户")
    parser.add_argument("--interval", type=float, default=2.0, help="两次采样间隔秒数，默认 2")
    parser.add_argument("--top", type=int, default=10, help="展示前 N 个高流量进程，默认 10")
    parser.add_argument("--history-only", action="store_true", help="仅检查历史流量来源，不做实时采样")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        target_uid = pwd.getpwnam(args.user).pw_uid
    except KeyError:
        print(f"用户不存在: {args.user}", file=sys.stderr)
        return 2

    if args.history_only:
        return print_history_summary()

    print(f"目标用户: {args.user} (uid={target_uid})")
    print(f"采样间隔: {args.interval:.1f}s")
    first = sample_user_traffic(target_uid)
    time.sleep(args.interval)
    second = sample_user_traffic(target_uid)
    rows = diff_samples(first, second, args.interval)

    if not rows:
        print("未采集到该用户下带字节统计的活动 TCP 连接。")
    else:
        print_table(rows, args.top)

    print()
    print("历史流量检查:")
    print_history_summary()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/bin/python3
import os
import glob
import argparse
import subprocess
from tqdm.auto import tqdm
import re


# { (error_tag, bt_str) -> [crash_file, ...] }
crash_groups: dict[tuple[str, str], list[str]] = {}


def check_aslr():
    with open("/proc/sys/kernel/randomize_va_space") as f:
        if f.read().strip() != "0":
            print(
                "Please disable ASLR: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
            )
            exit(1)


def parse_report(report: str) -> tuple[str, str]:
    errors = re.findall(
        r"\[!\] SGXSan ERROR:[^\n]*" r"|ERROR: libFuzzer:.*",
        report,
    )
    error_tag = " | ".join(errors)

    bt_str = ""
    m = re.search(
        r"\[\*\] SGXSan Backtrace:\s*\n(.*?)(?=---- ecall to enclave ----|$)",
        report,
        re.DOTALL,
    )
    if m:
        addr_lines = re.findall(r"0x[0-9a-fA-F]+:.*", m.group(1))
        bt_str = "\n".join(addr_lines)

    if "NOTE: fuzzing was not performed, you have only" in report:
        error_tag, bt_str = "", ""

    return error_tag, bt_str


def filter_crashes(test_dir, extra_opt, timeout):
    binary = os.path.join(test_dir, "TestApp")
    crashes_dir = os.path.join(test_dir, "result", "crashes")
    for p, check in [(binary, os.path.isfile), (crashes_dir, os.path.isdir)]:
        if not check(p):
            raise FileNotFoundError(f"Path not found: {p}")

    env = os.environ.copy()
    lib_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "install", "enclave_fuzz", "lib64",
    )
    env["LD_LIBRARY_PATH"] = lib_path + (
        ":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else ""
    )

    pbar = tqdm(sorted(glob.glob(os.path.join(crashes_dir, "crash-*"))))
    for crash_file in pbar:
        cmd = [binary, crash_file] + (extra_opt or [])
        try:
            result = subprocess.run(
                cmd,
                timeout=timeout,
                cwd=test_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            report = result.stdout.decode("utf-8", errors="backslashreplace")
            error_tag, bt_str = parse_report(report)
            crash_groups.setdefault((error_tag, bt_str), []).append(
                os.path.basename(crash_file)
            )
        except subprocess.TimeoutExpired:
            print(f"\nTimeout: {crash_file}")
        pbar.update()
    pbar.close()


def print_results():
    for i, ((error_tag, bt_str), inputs) in enumerate(crash_groups.items(), 1):
        print(f"{'='*60} [{i}/{len(crash_groups)}]")
        if error_tag:
            print(error_tag)
        if bt_str:
            print(bt_str)
        print(f"Crashes ({len(inputs)}):")
        for f in inputs:
            print(f"  {f}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Filter and group crashes by backtrace")
    parser.add_argument(
        "workdir",
        nargs="?",
        default=".",
        help="Work directory (contains TestApp and result/crashes/), default: current dir",
    )
    parser.add_argument("--extra-opt", nargs="+")
    parser.add_argument("--timeout", default=60, type=int)
    args = parser.parse_args()

    check_aslr()

    filter_crashes(os.path.abspath(args.workdir), args.extra_opt, args.timeout)
    print_results()


if __name__ == "__main__":
    main()

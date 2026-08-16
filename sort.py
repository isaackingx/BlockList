#!/usr/bin/env python3
"""
Read IP addresses from an input file, remove duplicates, sort them,
and write the unique, sorted IPs to an output file.

Usage:
    python dedupe_ips.py input.txt output.txt
"""

import sys
import os
import ipaddress


def read_ips(input_file):
    """
    Read IPs from file. Handles one IP per line, or multiple IPs on the
    same line separated by whitespace (spaces/tabs).
    """
    ips = []
    with open(input_file, "r") as f:
        for line in f:
            # split() with no args splits on any whitespace and drops empties
            ips.extend(line.split())
    return ips


def sort_key(ip_str):
    """
    Sort key that handles both valid IP addresses (numerically/properly)
    and any malformed entries (falls back to string sort, pushed to the end).
    """
    try:
        return (0, ipaddress.ip_address(ip_str))
    except ValueError:
        return (1, ip_str)


def dedupe_and_sort(ips):
    unique_ips = set(ips)
    return sorted(unique_ips, key=sort_key)


def write_ips(output_file, ips):
    with open(output_file, "w") as f:
        for ip in ips:
            f.write(ip + "\n")


def main():
    # Figure out the folder this script lives in, so input.txt/output.txt
    # are always found relative to the script -- not wherever the terminal
    # happens to be "cd"'d into.
    script_dir = os.path.dirname(os.path.abspath(__file__))

    default_input = os.path.join(script_dir, "input.txt")
    default_output = os.path.join(script_dir, "output.txt")

    input_file = sys.argv[1] if len(sys.argv) > 1 else default_input
    output_file = sys.argv[2] if len(sys.argv) > 2 else default_output

    print(f"Script folder:   {script_dir}")
    print(f"Looking for:     {input_file}")
    print(f"Will write to:   {output_file}")

    files_here = os.listdir(script_dir)
    print(f"Files in script folder: {files_here}")

    if not os.path.isfile(input_file):
        print(f"\nERROR: '{input_file}' was not found.")
        print("Check the exact filename above against the list of files "
              "in the folder -- watch out for a hidden '.txt.txt' extension "
              "or a trailing space in the name.")
        input("Press Enter to exit...")
        sys.exit(1)

    try:
        ips = read_ips(input_file)
    except FileNotFoundError:
        print(f"ERROR: Could not find '{input_file}'. "
              f"Make sure it's in the same folder as this script.")
        input("Press Enter to exit...")
        sys.exit(1)

    print(f"Read {len(ips)} IP entries from '{input_file}'")

    unique_sorted_ips = dedupe_and_sort(ips)
    print(f"Found {len(unique_sorted_ips)} unique IP(s)")

    write_ips(output_file, unique_sorted_ips)
    print(f"Wrote unique, sorted IPs to '{output_file}'")
    input("Press Enter to exit...")


if __name__ == "__main__":
    main() 
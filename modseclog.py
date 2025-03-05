#!/usr/bin/python3


# Copyright (C) 2025 Christian Göttsche
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


import argparse
import io
import re
import sys
from dataclasses import dataclass
from typing import TextIO

verbose = False


# --544ccf79-A--
header_pattern = re.compile(r'^--(?P<identifier>[a-zA-Z0-9]{8})-(?P<segment_type>A|B|C|E|F|H|I|J|K|Z)--$')

# [20/Jan/2025:10:08:30.463235 +0100] A42B7cP9_-4N31GLhv8UyABAAVo 1.2.3.4 57761 5.6.7.8 443
segment_a_pattern = re.compile(
    r'^\[(?P<timestamp>.+)\] [a-zA-Z0-9_-]+ (?P<source_ip>[0-9.:a-fA-F]+) (?P<source_port>[0-9]+) (?P<destination_ip>[0-9.:a-fA-F]+) (?P<destination_port>[0-9]+)$',
)

# Host: example.com
segment_b_host_pattern = re.compile(r'^(?:H|h)ost: (?P<requested_host>\S+)$')

# GET /sitecore/shell/sitecore.version.xml HTTP/1.1
segment_b_path_pattern = re.compile(r'^[A-Z]+ (?P<requested_path>\S+)')

# HTTP/1.1 404 Not Found
segment_f_status_pattern = re.compile(r'^\S+ (?P<status_code>[0-9]+) (?P<status_message>.+)$')

# Message: Warning. Pattern match "^[\\d.:]+$" at REQUEST_HEADERS:Host. [file "/usr/share/modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "735"] [id "920350"] [msg "Host header is a numeric IP address"] [data "1.2.3.4"] [severity "WARNING"] [ver "OWASP_CRS/3.3.7"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"]
segment_h_warning_pattern = re.compile(
    r'^Message: Warning\. .* \[id "(?P<rule_id>[0-9]+)"\] .*\[msg "(?P<rule_description>[^"\t\n\r]+)"\] (?:\[data "(?P<rule_data>[^"\t\n\r]+)"\] )?.*\[severity "(?P<rule_severity>[A-Z]+)"\].*$',
)


@dataclass
class Event:
    """Class for combined log events."""

    identifier: str
    timestamp: str | None
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    requested_host: str | None
    requested_path: str | None
    status_code: int | None
    status_message: str | None
    rule_id: int | None
    rule_description: str | None
    rule_severity: str | None
    rule_data: str | None


def analyze_file(file: TextIO) -> list[Event]:
    events = []

    current_identifier: str | None = None
    current_segment_type: str | None = None

    # A
    current_timestamp: str | None = None
    current_source_ip: str | None = None
    current_source_port: int | None = None
    current_destination_ip: str | None = None
    current_destination_port: int | None = None
    # B
    current_requested_host: str | None = None
    current_requested_path: str | None = None
    # F
    current_status_code: int | None = None
    current_status_message = None
    # H
    current_rule_id: int | None = None
    current_rule_description: str | None = None
    current_rule_severity: str | None = None
    current_rule_data: str | None = None

    lineno = 0

    for line in file:
        lineno += 1

        header_match = re.match(header_pattern, line)
        if header_match:
            identifier = header_match.group('identifier')
            segment_type = header_match.group('segment_type')

            if verbose:
                print(f"Found identifier {identifier} with segment type {segment_type}")

            if current_identifier is not None and current_identifier != identifier:
                print(
                    f"WARN: event {current_identifier} not closed (last segment {current_segment_type}), identifier {identifier} with segment {segment_type} found",
                )

            if current_identifier is None and segment_type != 'A':
                print(f"WARN: event {current_identifier} does not start with segment 'A', found {segment_type}")

            if segment_type == 'Z':
                if current_timestamp is None:
                    print(f"WARN: event {current_identifier} has no timestamp")
                if current_source_ip is None:
                    print(f"WARN: event {current_identifier} has no source ip")
                if current_source_port is None:
                    print(f"WARN: event {current_identifier} has no source port")
                if current_destination_ip is None:
                    print(f"WARN: event {current_identifier} has no destination ip")
                if current_destination_port is None:
                    print(f"WARN: event {current_identifier} has no destination port")
                if current_status_code is None:
                    print(f"WARN: event {current_identifier} has no status code")
                if current_status_message is None:
                    print(f"WARN: event {current_identifier} has no status message")

                ev = Event(
                    identifier,
                    current_timestamp,
                    current_source_ip,
                    current_source_port,
                    current_destination_ip,
                    current_destination_port,
                    current_requested_host,
                    current_requested_path,
                    current_status_code,
                    current_status_message,
                    current_rule_id,
                    current_rule_description,
                    current_rule_severity,
                    current_rule_data,
                )

                events.append(ev)

                current_identifier = None
                current_timestamp = None
                current_source_ip = None
                current_source_port = None
                current_destination_ip = None
                current_destination_port = None
                current_requested_host = None
                current_requested_path = None
                current_status_code = None
                current_status_message = None
                current_rule_id = None
                current_rule_description = None
                current_rule_severity = None
                current_rule_data = None
            else:
                current_identifier = identifier

            current_segment_type = segment_type

            continue

        if current_segment_type == 'A':
            match = re.match(segment_a_pattern, line)
            if match:
                current_timestamp = match.group('timestamp')
                current_source_ip = match.group('source_ip')
                current_source_port = int(match.group('source_port'))
                current_destination_ip = match.group('destination_ip')
                current_destination_port = int(match.group('destination_port'))
                if verbose:
                    print(
                        f"Found timestamp {current_timestamp} and source ip {current_source_ip} with port {current_source_port} and destination ip {current_destination_ip} with port {current_destination_port}",
                    )
            else:
                print(f"WARN: line {lineno}: segment A contains invalid content: '{line}'")

            continue

        if current_segment_type == 'B':
            match = re.match(segment_b_host_pattern, line)
            if match:
                current_requested_host = match.group('requested_host')
                if verbose:
                    print(f"Found requested host {current_requested_host}")

                continue

            match = re.match(segment_b_path_pattern, line)
            if match:
                current_requested_path = match.group('requested_path')
                if verbose:
                    print(f"Found requested path {current_requested_path}")

                continue

            continue

        if current_segment_type == 'F':
            match = re.match(segment_f_status_pattern, line)
            if match:
                current_status_code = int(match.group('status_code'))
                current_status_message = match.group('status_message')
                if verbose:
                    print(f"Found status code {current_status_code} with message '{current_status_message}'")

            continue

        if current_segment_type == 'H':
            match = re.match(segment_h_warning_pattern, line)
            if match:
                current_rule_id = int(match.group('rule_id'))
                current_rule_description = match.group('rule_description')
                current_rule_severity = match.group('rule_severity')
                current_rule_data = match.group('rule_data')
                if verbose:
                    print(
                        f"Found rule with ID {current_rule_id} of severity {current_rule_severity} and description '{current_rule_description}' with data '{current_rule_data}'",
                    )

            continue

    if current_identifier is not None:
        print(
            f"WARN: identifier {current_identifier} not closed (last segment {current_segment_type}), end-of-file reached",
        )

    return events


def analyze_events(events: list[Event], args: argparse.Namespace) -> None:
    class Counter[T](dict[T, int]):
        def __missing__(self, key: T) -> int:
            return 0

    top: int = -1 if args.number < 0 else args.number

    if args.with_rule:
        print('Excluding events without an associated rule')
    if args.source_ip:
        print(f"Limiting output to source IPs {args.source_ip}")
    if args.exclude_source_ip:
        print(f"Excluding source IPs {args.exclude_source_ip}")
    if args.destination_ip:
        print(f"Limiting output to destination IPs {args.destination_ip}")
    if args.exclude_destination_ip:
        print(f"Excluding destination IPs {args.exclude_destination_ip}")
    if args.host:
        print(f"Limiting output to requested hosts {args.host}")
    if args.exclude_host:
        print(f"Excluding requested hosts {args.exclude_host}")
    if args.path:
        print(f"Limiting output to requested paths {args.path}")
    if args.exclude_path:
        print(f"Excluding requested paths {args.exclude_path}")
    if args.rule:
        print(f"Limiting output to rules {args.rule}")
    if args.exclude_rule:
        print(f"Excluding rules {args.exclude_rule}")
    if args.severity:
        print(f"Limiting output to severities {args.severity}")
    if args.exclude_severity:
        print(f"Excluding severities {args.exclude_severity}")
    if args.status:
        print(f"Limiting output to HTTP response status {args.status}")
    if args.exclude_status:
        print(f"Excluding HTTP response status {args.exclude_status}")

    matched_events: list[Event] = []
    rule_events: int = 0
    source_ips: Counter[str] = Counter()
    destination_ips: Counter[str] = Counter()
    requested_hosts: Counter[str] = Counter()
    requested_paths: Counter[str] = Counter()
    rule_ids: Counter[int] = Counter()
    rule_severities: Counter[str] = Counter()
    rule_description_map: dict[int, str] = {}
    status_codes: Counter[int] = Counter()
    status_message_map: dict[int, str] = {}

    for ev in events:
        if args.with_rule and ev.rule_id is None:
            continue

        if args.source_ip and len(args.source_ip) > 0 and (ev.source_ip is None or ev.source_ip not in args.source_ip):
            continue

        if (
            args.exclude_source_ip
            and len(args.exclude_source_ip) > 0
            and ev.source_ip is not None
            and ev.source_ip in args.exclude_source_ip
        ):
            continue

        if (
            args.destination_ip
            and len(args.destination_ip) > 0
            and (ev.destination_ip is None or ev.destination_ip not in args.destination_ip)
        ):
            continue

        if (
            args.exclude_destination_ip
            and len(args.exclude_destination_ip) > 0
            and ev.destination_ip is not None
            and ev.destination_ip in args.exclude_destination_ip
        ):
            continue

        if args.host and len(args.host) > 0 and (ev.requested_host is None or ev.requested_host not in args.host):
            continue

        if (
            args.exclude_host
            and len(args.exclude_host) > 0
            and ev.requested_host is not None
            and ev.requested_host in args.exclude_host
        ):
            continue

        if args.path and len(args.path) > 0 and (ev.requested_path is None or ev.requested_path not in args.path):
            continue

        if (
            args.exclude_path
            and len(args.exclude_path) > 0
            and ev.requested_path is not None
            and ev.requested_path in args.exclude_path
        ):
            continue

        if args.rule and len(args.rule) > 0 and (ev.rule_id is None or ev.rule_id not in args.rule):
            continue

        if (
            args.exclude_rule
            and len(args.exclude_rule) > 0
            and ev.rule_id is not None
            and ev.rule_id in args.exclude_rule
        ):
            continue

        if (
            args.severity
            and len(args.severity) > 0
            and (ev.rule_severity is None or ev.rule_severity.casefold() not in args.severity)
        ):
            continue

        if (
            args.exclude_severity
            and len(args.exclude_severity) > 0
            and ev.rule_severity is not None
            and ev.rule_severity.casefold() in args.exclude_severity
        ):
            continue

        if args.status and len(args.status) > 0 and (ev.status_code is None or ev.status_code not in args.status):
            continue

        if (
            args.exclude_status
            and len(args.exclude_status) > 0
            and ev.status_code is not None
            and ev.status_code in args.exclude_status
        ):
            continue

        matched_events.append(ev)

        if ev.rule_id is not None:
            rule_events += 1
            rule_ids[ev.rule_id] += 1
            if ev.rule_description is not None:
                rule_description_map[ev.rule_id] = ev.rule_description

        if ev.rule_severity is not None:
            rule_severities[ev.rule_severity] += 1

        if ev.source_ip is not None:
            source_ips[ev.source_ip] += 1

        if ev.destination_ip is not None:
            destination_ips[ev.destination_ip] += 1

        if ev.requested_host is not None:
            requested_hosts[ev.requested_host] += 1

        if ev.requested_path is not None:
            requested_paths[ev.requested_path] += 1

        if ev.status_code is not None:
            status_codes[ev.status_code] += 1
            if ev.status_message is not None:
                status_message_map[ev.status_code] = ev.status_message

    num_matches = len(matched_events)
    print(f"Found {len(events)} total events, {num_matches} matching events, and {rule_events} events with a rule")
    if num_matches == 0:
        return

    if not args.source_ip or len(args.source_ip) != 1:
        print()
        source_ips_sorted = sorted(source_ips.items(), key=lambda kv: -kv[1])
        n = len(source_ips_sorted)
        print(f"Found {n} distinct source IPs", end='')
        if not args.list_source_ips and top > 0 and top < n:
            print(f"  --  Top {top}:")
            n = top
        else:
            print()
        for key, value in source_ips_sorted[:n]:
            print(f"\t({100 * value / num_matches:4.1f}% :: {value})\t{key}")

    if not args.destination_ip or len(args.destination_ip) != 1:
        print()
        destination_ips_sorted = sorted(destination_ips.items(), key=lambda kv: -kv[1])
        n = len(destination_ips_sorted)
        print(f"Found {n} distinct destination IPs", end='')
        if not args.list_destination_ips and top > 0 and top < n:
            print(f"  --  Top {top}:")
            n = top
        else:
            print()
        for key, value in destination_ips_sorted[:n]:
            print(f"\t({100 * value / num_matches:4.1f}% :: {value})\t{key}")

    if not args.host or len(args.host) != 1:
        print()
        requested_hosts_sorted = sorted(requested_hosts.items(), key=lambda kv: -kv[1])
        n = len(requested_hosts_sorted)
        print(f"Found {n} distinct requested hosts", end='')
        if not args.list_hosts and top > 0 and top < n:
            print(f"  --  Top {top}:")
            n = top
        else:
            print()
        for key, value in requested_hosts_sorted[:n]:
            print(f"\t({100 * value / num_matches:4.1f}% :: {value})\t{key}")

    if not args.path or len(args.path) != 1:
        print()
        requested_paths_sorted = sorted(requested_paths.items(), key=lambda kv: -kv[1])
        n = len(requested_paths_sorted)
        print(f"Found {n} distinct requested paths", end='')
        if not args.list_paths and top > 0 and top < n:
            print(f"  --  Top {top}:")
            n = top
        else:
            print()
        for key, value in requested_paths_sorted[:n]:
            print(f"\t({100 * value / num_matches:4.1f}% :: {value})\t{key}")

    if not args.rule or len(args.rule) != 1:
        print()
        rule_ids_sorted = sorted(rule_ids.items(), key=lambda kv: -kv[1])
        n = len(rule_ids_sorted)
        print(f"Found {n} distinct rules", end='')
        if not args.list_rules and top > 0 and top < n:
            print(f"  --  Top {top}:")
            n = top
        else:
            print()
        for key_int, value in rule_ids_sorted[:n]:
            print(f"\t({100 * value / num_matches:4.1f}% :: {value})\t{key_int}\t\t{rule_description_map[key_int]}")

    if not args.severity or len(args.severity) != 1:
        print()
        rule_severities_sorted = sorted(rule_severities.items(), key=lambda kv: -kv[1])
        n = len(rule_severities_sorted)
        print(f"Found {n} distinct rule severities", end='')
        if not args.list_severities and top > 0 and top < n:
            print(f"  --  Top {top}:")
            n = top
        else:
            print()
        for key, value in rule_severities_sorted[:n]:
            print(f"\t({100 * value / num_matches:4.1f}% :: {value})\t{key}")

    if not args.status or len(args.status) != 1:
        print()
        status_codes_sorted = sorted(status_codes.items(), key=lambda kv: -kv[1])
        n = len(status_codes_sorted)
        print(f"Found {n} distinct status codes", end='')
        if not args.list_statuses and top > 0 and top < n:
            print(f"  --  Top {top}:")
            n = top
        else:
            print()
        for key_int, value in status_codes_sorted[:n]:
            print(f"\t({100 * value / num_matches:4.1f}% :: {value})\t{key_int}\t\t{status_message_map[key_int]}")

    if args.expand:
        for ev in matched_events:
            print()
            print(f"Event {ev.identifier}:")
            print(f"\ttimestamp:         {ev.timestamp}")
            print(f"\tsource ip:         {ev.source_ip}")
            print(f"\tsource port:       {ev.source_port}")
            print(f"\tdestination ip:    {ev.destination_ip}")
            print(f"\tdestination port:  {ev.destination_port}")
            print(f"\trequested host:    {ev.requested_host}")
            print(f"\trequested path:    {ev.requested_path}")
            print(f"\tstatus code:       {ev.status_code}")
            print(f"\tstatus message:    {ev.status_message}")
            print(f"\trule id:           {ev.rule_id}")
            print(f"\trule description:  {ev.rule_description}")
            print(f"\trule severity:     {ev.rule_severity}")
            print(f"\trule data:         {ev.rule_data}")


def main() -> int:
    parser = argparse.ArgumentParser(prog='ModSecLog', description='Mod Security Log Analyzer')

    parser.add_argument(
        'file',
        metavar='FILE',
        type=argparse.FileType('r', errors='replace'),
        default=(
            None if sys.stdin.isatty() else io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8', errors='replace')
        ),
        nargs='?',
        help='the file to analyze; content can also be piped into this program',
    )
    parser.add_argument(
        '-d',
        '--destination-ip',
        type=str,
        action='append',
        help='show only events with the given destination IP; can be specified multiple times',
    )
    parser.add_argument(
        '-D',
        '--exclude-destination-ip',
        type=str,
        action='append',
        help='do not show events with the given destination IP; can be specified multiple times',
    )
    parser.add_argument(
        '--list-destination-ips',
        action='store_true',
        help='show all destination IPs',
    )
    parser.add_argument(
        '--list-hosts',
        action='store_true',
        help='show all requested hosts',
    )
    parser.add_argument(
        '--list-paths',
        action='store_true',
        help='show all requested paths',
    )
    parser.add_argument(
        '--list-rules',
        action='store_true',
        help='show all affected rules',
    )
    parser.add_argument(
        '--list-severities',
        action='store_true',
        help='show all rule severities',
    )
    parser.add_argument(
        '--list-source-ips',
        action='store_true',
        help='show all source IPs',
    )
    parser.add_argument(
        '--list-statuses',
        action='store_true',
        help='show all HTTP response statuses',
    )
    parser.add_argument(
        '-n',
        '--number',
        type=int,
        default=3,
        action='store',
        help='the number of top elements to display (use -1 to show all; defaults to 10)',
    )
    parser.add_argument(
        '-p',
        '--path',
        type=str,
        action='append',
        help='show only events with the given requested path; can be specified multiple times',
    )
    parser.add_argument(
        '-P',
        '--exclude-path',
        type=str,
        action='append',
        help='do not show events with the given requetsted path; can be specified multiple times',
    )
    parser.add_argument(
        '-q',
        '--host',
        type=str,
        action='append',
        help='show only events with the given requested host; can be specified multiple times',
    )
    parser.add_argument(
        '-Q',
        '--exclude-host',
        type=str,
        action='append',
        help='do not show events with the given requetsted host; can be specified multiple times',
    )
    parser.add_argument(
        '-r',
        '--rule',
        type=int,
        action='append',
        help='show only events with the given rule ID; can be specified multiple times',
    )
    parser.add_argument(
        '-R',
        '--exclude-rule',
        type=int,
        action='append',
        help='do not show events with the given rule ID; can be specified multiple times',
    )
    parser.add_argument(
        '-s',
        '--source-ip',
        type=str,
        action='append',
        help='show only events with the given source IP; can be specified multiple times',
    )
    parser.add_argument(
        '-S',
        '--exclude-source-ip',
        type=str,
        action='append',
        help='do not show events with the given source IP; can be specified multiple times',
    )
    parser.add_argument(
        '-t',
        '--status',
        type=int,
        action='append',
        help='show only events with the given HTTP response status; can be specified multiple times',
    )
    parser.add_argument(
        '-T',
        '--exclude-status',
        type=int,
        action='append',
        help='do not show events with the given HTTP response status; can be specified multiple times',
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='more verbose program output')
    parser.add_argument(
        '-w', '--with-rule', action='store_true', help='show only events with a matched ModSecurity rule'
    )
    parser.add_argument('-x', '--expand', action='store_true', help='show the event details')
    parser.add_argument(
        '-y',
        '--severity',
        type=str,
        action='append',
        help='show only events with the given severity; can be specified multiple times',
    )
    parser.add_argument(
        '-Y',
        '--exclude-severity',
        type=str,
        action='append',
        help='do not show events with the given severity; can be specified multiple times',
    )

    args = parser.parse_args()
    global verbose
    verbose = args.verbose

    if args.file is None:
        parser.print_help()
        return -1

    if args.destination_ip and args.exclude_destination_ip:
        common_destination_ip = [item for item in args.destination_ip if item in args.exclude_destination_ip]
        if common_destination_ip:
            print(f"destination IP {common_destination_ip} use conflict!")
            return -1

    if args.path and args.exclude_path:
        common_path = [item for item in args.path if item in args.exclude_path]
        if common_path:
            print(f"path {common_path} use conflict!")
            return -1

    if args.host and args.exclude_host:
        common_host = [item for item in args.host if item in args.exclude_host]
        if common_host:
            print(f"host {common_host} use conflict!")
            return -1

    if args.rule and args.exclude_rule:
        common_rule = [item for item in args.rule if item in args.exclude_rule]
        if common_rule:
            print(f"rule {common_rule} use conflict!")
            return -1

    if args.source_ip and args.exclude_source_ip:
        common_source_ip = [item for item in args.source_ip if item in args.exclude_source_ip]
        if common_source_ip:
            print(f"source IP {common_source_ip} use conflict!")
            return -1

    if args.status and args.exclude_status:
        common_status = [item for item in args.status if item in args.exclude_status]
        if common_status:
            print(f"status {common_status} use conflict!")
            return -1

    if args.severity and args.exclude_severity:
        common_severity = [item for item in args.severity if item in args.exclude_severity]
        if common_severity:
            print(f"severity {common_severity} use conflict!")
            return -1

    events = analyze_file(args.file)

    analyze_events(events, args)

    return 0


if __name__ == '__main__':
    sys.exit(main())

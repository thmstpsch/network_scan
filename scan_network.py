#!/usr/bin/env python3
"""List local Ethernet interfaces and scan a selected network with nmap."""

import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def command_output(command):
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return ""


def network_from_ip(ip, prefix):
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return ""


def linux_interfaces():
    try:
        data = json.loads(command_output(["ip", "-j", "-4", "addr", "show"]) or "[]")
    except json.JSONDecodeError:
        return []
    interfaces = []
    for item in data:
        name = item.get("ifname", "")
        if not name.startswith("e") or name == "lo":
            continue
        address = next((entry for entry in item.get("addr_info", [])
                        if entry.get("family") == "inet"), None)
        if address:
            ip = address["local"]
            prefix = address["prefixlen"]
            interfaces.append({"name": name, "ip": ip, "cidr": f"{ip}/{prefix}",
                               "subnet": network_from_ip(ip, prefix)})
        else:
            interfaces.append({"name": name, "ip": "", "cidr": "", "subnet": ""})
    return interfaces


def windows_interfaces():
    text = command_output(["ipconfig", "/all"])
    interfaces = []
    current = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line and not raw_line.startswith((" ", "\t")) and line.endswith(":"):
            if current:
                interfaces.append(current)
            adapter_name = re.sub(r"^.*\badapter\s+", "", line[:-1], flags=re.IGNORECASE)
            current = {"name": adapter_name, "ip": "", "cidr": "", "subnet": ""}
        if current and ("IPv4 Address" in line or "IPv4-Adresse" in line):
            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if match:
                current["ip"] = match.group(1)
        if current and ("Subnet Mask" in line or "Subnetzmaske" in line):
            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if match and current["ip"]:
                try:
                    prefix = ipaddress.ip_network(f"0.0.0.0/{match.group(1)}").prefixlen
                    current["cidr"] = f"{current['ip']}/{prefix}"
                    current["subnet"] = network_from_ip(current["ip"], prefix)
                except ValueError:
                    pass
    if current:
        interfaces.append(current)
    return [item for item in interfaces if item["name"] and not item["name"].lower().startswith("loopback")]


def interfaces():
    return windows_interfaces() if os.name == "nt" else linux_interfaces()


def run_scan(command, output_file, mode="w"):
    try:
        with output_file.open(mode, encoding="utf-8") as output:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True)
            for line in process.stdout:
                print(line, end="")
                output.write(line)
            return process.wait()
    except OSError as error:
        print(f"Unable to run scanner: {error}")
        return 1


def with_privilege(command):
    if os.name != "nt" and os.geteuid() != 0 and shutil.which("sudo"):
        return ["sudo", *command]
    return command


def nmap_scan_command(target, interface):
    command = ["nmap", "-sn", target]
    if os.name != "nt":
        command.extend(["-e", interface])
    return command


def neighbor_subnets(interface, own_subnet):
    command = ["arp", "-a"] if os.name == "nt" else ["ip", "neigh", "show", "dev", interface]
    own_network = ipaddress.ip_network(own_subnet, strict=False)
    networks = set()
    for address in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", command_output(command)):
        try:
            host = ipaddress.ip_address(address)
            if host not in own_network:
                networks.add(str(ipaddress.ip_network(f"{host}/24", strict=False)))
        except ValueError:
            continue
    return sorted(networks)


def main():
    system = platform.system()
    print(f"Detected operating system: {system}")
    if not shutil.which("nmap"):
        print("nmap is required and was not found in PATH.")
        return 1

    found = interfaces()
    if not found:
        print("No Ethernet interfaces with IPv4 information were found.")
        return 1
    print("Available ethernet interfaces:")
    for index, item in enumerate(found):
        if item["cidr"]:
            print(f"{index}) {item['name']:<20} | IP: {item['ip']:<15} | CIDR: {item['cidr']:<18} | Subnet: {item['subnet']}")
        else:
            print(f"{index}) {item['name']:<20} | IP: (none - interface has no IPv4 address)")

    try:
        index = int(input("Select an interface by number: "))
        selected = found[index]
    except (ValueError, EOFError, KeyboardInterrupt, IndexError):
        print("Invalid selection.")
        return 1
    if not selected["cidr"]:
        print(f"No IPv4 address found for {selected['name']}.")
        return 1

    subnet = selected["subnet"] or selected["cidr"]
    print(f"\nSelected interface : {selected['name']}\nInterface IP       : {selected['ip']}\nInterface CIDR     : {selected['cidr']}\nNetwork subnet     : {subnet}\n")
    print(f"  1) My subnet only ({subnet})")
    print("  2) My subnet AND other subnets on the same physical network")
    scan_other = input("Select scan scope [1/2] (default 1): ").strip() == "2"
    output_file = Path(f"network_scan_{selected['name']}.log")
    command = with_privilege(nmap_scan_command(subnet, selected["name"]))
    print(f"\nScanning network {subnet} on interface {selected['name']}...")
    if run_scan(command, output_file):
        return 1
    print(f"Scan complete. Results saved to {output_file}.")
    if not scan_other:
        return 0

    detected = neighbor_subnets(selected["name"], subnet)
    if detected:
        print("Neighbor-table subnets detected: " + ", ".join(detected))
    elif os.name == "nt":
        print("No out-of-subnet neighbors found; use additional ranges below.")
    else:
        print("No out-of-subnet neighbors found; use additional ranges below.")
    extra = input("Enter additional subnet(s)/range(s) to scan (space separated) or leave empty: ").split()
    targets = detected + extra
    if not targets:
        print("No other subnets to actively scan.")
        return 0
    other_output = Path(f"network_scan_{selected['name']}_other_subnets.log")
    scanner = "arp-scan" if shutil.which("arp-scan") and os.name != "nt" else "nmap"
    with other_output.open("w", encoding="utf-8") as output:
        for target in targets:
            print(f"\n>>> Scanning {target} on {selected['name']}")
            output.write(f"\n>>> Scanning {target} on {selected['name']}\n")
            command = ([scanner, "--interface=" + selected["name"], target]
                       if scanner == "arp-scan" else nmap_scan_command(target, selected["name"]))
            if run_scan(with_privilege(command), other_output, mode="a"):
                return 1
    print(f"\nOther-subnet scan complete. Results saved to {other_output}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
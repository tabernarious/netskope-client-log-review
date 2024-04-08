# PURPOSE: Parse nsdebuglog.log to highlight useful and important information
# WRITTEN BY: Daniel Tavernier (dtavernier@netskope.com) with initial help from ChatGPT
# LATEST CODE: https://github.com/tabernarious/netskope-client-log-review
# USAGE: python3 parse_nsdebuglog.py
# USAGE: python3 parse_nsdebuglog.py [custom path to nsdebuglog.log; default is /Library/Logs/Netskope/nsdebuglog.log]
# CHANGELOG:
#   20231118 - Initial release
#   20231211 - Fixed IP match for non-web traffic
#   20240208 - Added bypass to exception host (Domain)

# SUPPORTED EXAMPLE LOG LINES per Steering/Exception Type:
# Steering Exception: Cert-Pinned App
#   BypassAppMgr Bypassing connection from process: google drive, host: www.googleapis.com
# Steering Exception: Domain
#   BypassAppMgr bypassing flow to exception host: st3.zoom.us, process: google chrome helper, Dest IP: 52.84.151.63, Dest Port: 443
# Steering Exception: Destination Location - Local IP Address
#   BypassAppMgr Bypassing flow from process: spotify to private ip: 192.168.1.123, Port: 1400, host: 192.168.1.123
# Steering: Web Traffic (HTTP/S)
#   Tunneling flow from addr: 192.168.1.146:53405, process: kandji-daemon to host: rtc.iot.kandji.io, addr: 54.185.70.68:443 to nsProxy
# Steering: Non-Web Traffic (Cloud Firewall)
#   Tunneling flow from addr: 192.168.1.161:53350, process: google chrome helper to host: 142.251.176.188, addr: 142.251.176.188:5228 to app-fw

# FUTURE EXAMPLE LOG LINES per Steering/Exception Type:
# Steering Exception: Application (Firewall App)
# Steering Exception: Application (Cloud App)
# Steering Exception: Category (does this look the same as Domains)
# Steering Exception: Cert-Pinned App with Tunnel Mode
# Steering Exception: Destination Location - Network Location
# Steering Exception: DNS (is this even logged?)
# Steering Exception: Source Locations
# Steering Exception: Source Countries
# Steering Exception: Bypass at Netskope Cloud (Legacy On-Premises Detection *or* Flexible Dynamic Steering)
# Steering: Endpoint DLP (does this log anything)
# Steering: DNS (is this even logged?)

import re
import argparse

# Steering Exception: Cert-Pinned App
def bypassing_connection_from_processes(log_file):
    process_host_map = {}

    process_pattern = r' Bypassing connection from process: (.+), host:'
    host_pattern = r' host: (.+)$'

    with open(log_file, 'r') as file:
        for line in file:
            process_match = re.search(process_pattern, line)

            if process_match:
                host_match = re.search(host_pattern, line)
    #            ip_match = re.search(ip_pattern, line)
    #            port_match = re.search(port_pattern, line)

                if process_match and host_match:
                    host_ip_port = host_match.group(1)
                    process_name = process_match.group(1).strip()

                    if process_name in process_host_map:
                        process_host_map[process_name].add(host_ip_port)
                    else:
                        process_host_map[process_name] = {host_ip_port}

    return process_host_map

# Steering Exception: Domain
def bypassing_flow_to_exception_host(log_file):
    process_host_map = {}

    process_pattern = r' process: (.+), Dest IP'
    host_pattern = r' bypassing flow to exception host: (.+), process:'
    ip_pattern = r' Dest IP: (.+), Dest Port'
    port_pattern = r' Port: ([0-9]+)$'

    with open(log_file, 'r') as file:
        for line in file:
            process_match = re.search(process_pattern, line)

            if process_match:
                host_match = re.search(host_pattern, line)
                ip_match = re.search(ip_pattern, line)
                port_match = re.search(port_pattern, line)

                if host_match and process_match and ip_match and port_match:
                    host_ip_port = host_match.group(1) + " (" + ip_match.group(1) + ":" + port_match.group(1) + ")"
                    process_name = process_match.group(1).strip()

                    if process_name in process_host_map:
                        process_host_map[process_name].add(host_ip_port)
                    else:
                        process_host_map[process_name] = {host_ip_port}

    return process_host_map

# Steering Exception: Destination Location - Local IP Address
def bypassing_flow_from_process_to_private_ip(log_file):
    process_host_map = {}

    process_pattern = r' Bypassing flow from process: (.+) to private ip'
    ip_pattern = r' private ip: (.+), Port'
#    host_pattern = r' host: (.+)$'
    port_pattern = r' Port: ([0-9]+), host'

    with open(log_file, 'r') as file:
        for line in file:
            process_match = re.search(process_pattern, line)

            if process_match:
    #            host_match = re.search(host_pattern, line)
                ip_match = re.search(ip_pattern, line)
                port_match = re.search(port_pattern, line)

                if process_match and ip_match and port_match:
                    current_ip = ip_match.group(1) + ":" + port_match.group(1)
                    process_name = process_match.group(1).strip()

                    if process_name in process_host_map:
                        process_host_map[process_name].add(current_ip)
                    else:
                        process_host_map[process_name] = {current_ip}

    return process_host_map

# Steering: Web Traffic (HTTP/S)
def tunneling_flow_to_nsproxy(log_file):
    process_host_map = {}

    process_pattern = r' Tunneling flow from addr: .*, process: (.+) to host:.*to nsProxy$'
    host_pattern = r' host: (.+),'
#    ip_pattern = r' addr: (.+):'
#    port_pattern = r' addr: .+:([0-9]+) '

    with open(log_file, 'r') as file:
        for line in file:
            process_match = re.search(process_pattern, line)

            if process_match:
                host_match = re.search(host_pattern, line)
    #            ip_match = re.search(ip_pattern, line)
    #            port_match = re.search(port_pattern, line)

                if process_match and host_match:
                    host_ip_port = host_match.group(1)
    #                host_ip_port = host_match.group(1) + ":" + port_match.group(1)
                    process_name = process_match.group(1).strip()

                    if process_name in process_host_map:
                        process_host_map[process_name].add(host_ip_port)
                    else:
                        process_host_map[process_name] = {host_ip_port}

    return process_host_map

# Steering: Non-Web Traffic (Cloud Firewall)
def tunneling_flow_to_appfw(log_file):
    process_host_map = {}

    process_pattern = r' Tunneling flow from addr: .*, process: (.+) to host:.*to app-fw$'
    host_pattern = r' host: (.+),'
    ip_pattern = r', addr: ([0-9.]+):'
    port_pattern = r' addr: [0-9.]+:([0-9]+) '

    with open(log_file, 'r') as file:
        for line in file:
            process_match = re.search(process_pattern, line)
            
            if process_match:
                host_match = re.search(host_pattern, line)
                ip_match = re.search(ip_pattern, line)
                port_match = re.search(port_pattern, line)

                if process_match and ip_match and port_match:
                    process_name = process_match.group(1).strip()

                    if host_match:
                        host_ip_port = host_match.group(1) + ":" + port_match.group(1) + " (" + ip_match.group(1) + ")"
                    else:
                        host_ip_port = ip_match.group(1) + ":" + port_match.group(1)

                    if process_name in process_host_map:
                        process_host_map[process_name].add(host_ip_port)
                    else:
                        process_host_map[process_name] = {host_ip_port}

    return process_host_map

def main():
    parser = argparse.ArgumentParser(description='Parse log file for process names and associated hosts')
    parser.add_argument('log_file', nargs='?', default='/Library/Logs/Netskope/nsdebuglog.log', help='Path to the log file')
    args = parser.parse_args()

    log_file_path = args.log_file
#    process_map_bypassing_flow_from_process_to_private_ip = bypassing_flow_from_process_to_private_ip(log_file_path)
#    process_map_bypassing_connection_from_processes = bypassing_connection_from_processes(log_file_path)
#    process_map_tunneling_flow_to_nsproxy = tunneling_flow_to_nsproxy(log_file_path)
#    process_map_tunneling_flow_to_appfw = tunneling_flow_to_appfw(log_file_path)

    print()
    print("################################\n##                            ##\n## Netskope Client Log Review ##\n##                            ##\n################################")

    print()
    print("##############################\n## Bypassed Connections to Private IPs\n##############################")
    for process, hosts in sorted(bypassing_flow_from_process_to_private_ip(log_file_path).items()):
        print(f"Process: {process}: {', '.join(sorted(hosts))}")

    print()
    print("##############################\n## Bypassed Connections from Cert-Pinned Apps\n##############################")
    for process, hosts in sorted(bypassing_connection_from_processes(log_file_path).items()):
        print(f"Process: {process}: {', '.join(sorted(hosts))}")

    print()
    print("##############################\n## Bypassed Connections to Domains\n##############################")
    for process, hosts in sorted(bypassing_flow_to_exception_host(log_file_path).items()):
        print(f"Process: {process}: {', '.join(sorted(hosts))}")

    print()
    print("##############################\n## Tunneled Web Traffic (nsProxy)\n##############################")
    for process, hosts in sorted(tunneling_flow_to_nsproxy(log_file_path).items()):
        print(f"Process: {process}: {', '.join(sorted(hosts))}")

    print()
    print("##############################\n## Tunneled Non-Web Traffic (app-fw)\n##############################")
    for process, hosts in sorted(tunneling_flow_to_appfw(log_file_path).items()):
        print(f"Process: {process}: {', '.join(sorted(hosts))}")

    print()

if __name__ == "__main__":
    main()

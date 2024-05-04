# PURPOSE: Parse nsdebuglog.log to highlight useful and important information
# WRITTEN BY: Daniel Tavernier (dtavernier@netskope.com) with initial help from ChatGPT
# LATEST CODE: https://github.com/tabernarious/netskope-client-log-review
# USAGE: python3 parse_nsdebuglog.py
# USAGE: python3 parse_nsdebuglog.py [custom path to nsdebuglog.log; default is /Library/Logs/Netskope/nsdebuglog.log]
# CHANGELOG:
#   20231118 - Initial release
#   20231211 - Fixed IP match for non-web traffic
#   20240208 - Added bypass to exception host (Domain)
#   20240209 - Updated future examples
#   20240428 - IPs are now listed when "host" is blank (often a sign of DNS issues)
#            - Reworked and cleaned up output headers; capitalized PROCESS
#            - Updated future examples
#   20240428 - Added "Steering Exceptions by Tunneling from Cert-Pinned Apps"
#   20240429 - Added per-OS default log file paths (as of R114)

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
#   (Steered to Netskope; SSL Do Not Decrypt applied; All policies bypassed)
# Steering Exception: Cert-Pinned App with Tunnel Mode
#   Tunnel domains must be a subset of the App Domains and Custom App Domains
#   Custom App Domains only include one level of sub-domain (example.com will include x.example.com but not y.x.example.com)
#   BypassAppMgr Bypassing connection by tunneling from process: msedgewebview2.exe, host: ok12static.oktacdn.com
#   2024/04/28 11:02:28.408 stAgentSvc p17fc tb44 info bypassAppMgr.cpp:669 BypassAppMgr Bypassing connection by tunneling from process: chrome.exe, host: udc.yahoo.com
#   2024/04/28 11:02:28.409 stAgentSvc p17fc tb44 info tunnel.cpp:878 nsTunnel DTLS [sessId 1] Tunneling flow from addr: 10.0.2.140:60894, process: chrome.exe to host: udc.yahoo.com, addr: 98.136.103.27:443 to
# Steering Exception: Cert-Pinned App with Managed Device (ignores Custom App Domains and applies bypass to all domains)
#   2024/04/28 02:04:54.302 stAgentSvc p1180 t1228 info bypassAppMgr.cpp:1150 BypassAppMgr Found process: chrome.exe to be bypassed for managed devices
#   2024/04/28 02:04:54.302 stAgentSvc p1180 t1228 info bypassAppMgr.cpp:1153 BypassAppMgr device classification status: managed
#   2024/04/28 02:04:54.302 stAgentSvc p1180 t1228 info bypassAppMgr.cpp:654 BypassAppMgr Bypassing connection from process: chrome.exe, host: optimizationguide-pa.googleapis.com
# Steering Exception: Cert-Pinned App Block (ignores Custom App Domains and blocks all domains)
#   2024/04/28 01:56:53.795 stAgentSvc p1fc tbac info bypassAppMgr.cpp:663 BypassAppMgr Dropping connection from process: chrome.exe, host: clientservices.googleapis.com
# Steering Exception: Destination Location - Network Location
# Steering Exception: DNS (is this even logged?)
# Steering Exception: Source Locations
# Steering Exception: Source Countries
#   (Steered to Netskope; SSL Do Not Decrypt applied; All policies bypassed)
# Steering Exception: Bypass at Netskope Cloud (Legacy On-Premises Detection *or* Flexible Dynamic Steering)
# Steering: Endpoint DLP (does this log anything)
# Steering: DNS (is this even logged?)
# Unknown
#   ExceptiontMgr IP 10.2.100.207 is found in IP address range Exception List
#   ExceptiontMgr IP address : 10.2.100.207 is in firewall exceptions

import re
import argparse
import platform

# Read and print first and last datestamps for context
def datestamps_first_last_line(log_file):
    #Example datestamp from nsdebuglog: 2024/04/30 16:50:14.733
    datestamp = r'^(20[0-9]{2}/[0-9]{2}/[0-9]{2}] [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{,3}) '

    with open(log_file) as file:
        log_lines = file.readlines()

        datestamp_first_line = re.search(process_pattern, log_lines[0])
        print(datestamp_first_line)

        datestamp_last_line = re.search(process_pattern, log_lines[-1])
        print(datestamp_last_line)

# Steering Exception: Cert-Pinned App
def bypassing_connection_from_process(log_file):
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

# Steering Exception: Cert-Pinned App Tunnel Mode
def bypassing_connection_by_tunneling_from_process(log_file):
    #2024/04/28 11:02:28.408 stAgentSvc p17fc tb44 info bypassAppMgr.cpp:669 BypassAppMgr Bypassing connection by tunneling from process: chrome.exe, host: udc.yahoo.com

    process_host_map = {}

    process_pattern = r' Bypassing connection by tunneling from process: (.+), host:'
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
    ip_pattern = r', addr: (.+):'
    #port_pattern = r', addr: .+:([0-9]+)'

    with open(log_file, 'r') as file:
        for line in file:
            process_match = re.search(process_pattern, line)

            if process_match:
                host_match = re.search(host_pattern, line)
                ip_match = re.search(ip_pattern, line)
                #port_match = re.search(port_pattern, line)

                if host_match:
                    host_ip_port = host_match.group(1)
                else:
                    host_ip_port = ip_match.group(1)
                    #host_ip_port = ip_match.group(1) + ":" + port_match.group(1)

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
    port_pattern = r', addr: [0-9.]+:([0-9]+)'

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
    #parser.add_argument('log_file', nargs='?', default='/Library/Logs/Netskope/nsdebuglog.log', help='Path to the log file')
    parser.add_argument('log_file', nargs='?', help='Path to the log file')
    args = parser.parse_args()
    system_os = platform.system()

    if args.log_file:
        log_file_path = args.log_file
        print("Log file specified")
        print("Using: " + log_file_path)
    elif system_os == "Windows":
        log_file_path = 'C:\ProgramData\netskope\stagent\Logs\nsdebuglog.log'
        print("No log file specified")
        print("Using Windows default: " + log_file_path)
    elif system_os == "Linux":
        log_file_path = '/opt/netskope/stagent/log/nsdebuglog.log'
        print("No log file specified")
        print("Using Linux default: " + log_file_path)
    elif system_os == "Darwin":
        log_file_path = '/Library/Logs/Netskope/nsdebuglog.log'
        print("No log file specified")
        print("Using macOS default: " + log_file_path)
    else:
        print("No log file specified\nUnknown operating system\nExisting...")
        exit()

    print()
    print("################################\n")
    print("##                            ##\n")
    print("## Netskope Client Log Review ##\n")
    print("##                            ##\n")
    print("################################")

    print()
    datestamps_first_last_line(log_file_path)

    print()
    print("##############################################################################")
    print("## Steering Exceptions to Private IPs (not sent to Netskope Cloud)")
    print("##############################################################################")
    if len(bypassing_flow_from_process_to_private_ip(log_file_path)) == 0:
        print ("(none found)")
    else:
        for process, hosts in sorted(bypassing_flow_from_process_to_private_ip(log_file_path).items()):
            print(f"PROCESS: {process}: {', '.join(sorted(hosts))}")

    print()
    print("##############################################################################")
    print("## Steering Exceptions from Cert-Pinned Apps (not sent to Netskope Cloud)")
    print("##############################################################################")
    if len(bypassing_connection_from_process(log_file_path)) == 0:
        print ("(none found)")
    else:
        for process, hosts in sorted(bypassing_connection_from_process(log_file_path).items()):
            print(f"PROCESS: {process}: {', '.join(sorted(hosts))}")

    print()
    print("##############################################################################")
    print("## Steering Exceptions by Tunneling from Cert-Pinned Apps")
    print("## (sent to Netskope where decryption and all policies are bypassed)")
    print("## NOTE: These connections will be duplicated in \"Steered Web Traffic\" below.")
    print("##############################################################################")
    if len(bypassing_connection_by_tunneling_from_process(log_file_path)) == 0:
        print ("(none found)")
    else:
        for process, hosts in sorted(bypassing_connection_by_tunneling_from_process(log_file_path).items()):
            print(f"PROCESS: {process}: {', '.join(sorted(hosts))}")

    print()
    print("##############################################################################")
    print("## Steering Exceptions to Domains (not sent to Netskope Cloud)")
    print("##############################################################################")
    if len(bypassing_flow_to_exception_host(log_file_path)) == 0:
        print ("(none found)")
    else:
        for process, hosts in sorted(bypassing_flow_to_exception_host(log_file_path).items()):
            print(f"PROCESS: {process}: {', '.join(sorted(hosts))}")

    print()
    print("##############################################################################")
    print("## Steered Web Traffic (HTTP/S) (sent to Netskope NG-SWG \"nsProxy\")")
    print("## NOTE: Category and Destination Country Steering Exceptions are steered")
    print("##       to Netskope where decryption and all policies are bypassed.")
    print("##############################################################################")
    if len(tunneling_flow_to_nsproxy(log_file_path)) == 0:
        print ("(none found)")
    else:
        for process, hosts in sorted(tunneling_flow_to_nsproxy(log_file_path).items()):
            print(f"PROCESS: {process}: {', '.join(sorted(hosts))}")

    print()
    print("##############################################################################")
    print("## Steered Non-Web Traffic (sent to Netskope Cloud Firewall \"app-fw\")")
    print("##############################################################################")
    if len(tunneling_flow_to_appfw(log_file_path)) == 0:
        print ("(none found)")
    else:
        for process, hosts in sorted(tunneling_flow_to_appfw(log_file_path).items()):
            print(f"PROCESS: {process}: {', '.join(sorted(hosts))}")

    print()

if __name__ == "__main__":
    main()

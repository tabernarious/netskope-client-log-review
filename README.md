# netskope-client-log-review
Parse and highlight information from Netskope Client Logs

## Example Output
Example output produced by:
* `parse_nsdebuglog.py`
  * See `nsdebuglog.log-PARSED-EXAMPLE.txt`

## parse_nsdebuglog.py
### Purpose
Parse nsdebuglog.log to highlight useful and important information:
* Steering Exceptions
* Per-process summary of domains/IPs accessed

### Usage and Examples
USAGE: `python3 parse_nsdebuglog.py [/path/to/nsdebuglog.log]`

EXAMPLE: `python3 parse_nsdebuglog.py`
* If no log file is specified the OS-specific default will be used:
  * Windows: C:\ProgramData\netskope\stagent\Logs\nsdebuglog.log
  * macOS: /Library/Logs/Netskope/nsdebuglog.log
  * Linux: /opt/netskope/stagent/log/nsdebuglog.log

EXAMPLE: `python3 parse_nsdebuglog.py /custom/path/to/nsdebuglog.log`
* The specified copy of `nsdebuglog.log` will be parsed.

## Enhancement Requests
* List start and end datetime stamp of parsed log
* List endpoint hostname
  * `Config setting STA user agent: hostname: this-pc-name`
* List Operating system of parsed log
  * `Config setting STA user agent: Windows NT 11.0 x64;Netskope ST Agent 111.0.0.1880;ID-PF4H9SYA`
* List Client versions seen
  * `Config setting STA user agent: Windows NT 11.0 x64;Netskope ST Agent 111.0.0.1880;ID-PF4H9SYA`
* List Netskope POPs connected to
  * `nsTunnel DTLS SSL connected to the gslbgw server: gateway-iad2.goskope.com(163.116.146.35):443 successfully`
* List endpoint source IPs in use
  * `Tunneling flow from addr: 2603:9000:5d00:1c:fdf0:9da5:xxxx:xxxx:59136`
  * `Tunneling flow from addr: 192.168.4.xxx:57425`
  * `nsUtils Pref src ip 2603:9000:5d00:1c:fdf0:9da5:xxxx:xxxx, iface 5`
  * `nsUtils Pref src ip 172.1.xxx.xxx, iface 21`
* List users seen
  * `nsImpersonate Current user: UserFirst.Lastname`
* Other log lines
  * `nsTunnel DTLS disconnecting nsTunnel, context = NSTUNNEL_DISCONNECTED_BYUSER`
  * `nsTunnel DTLS nsssl_connect failed, err: -1`
  * `nsssl DTLS failed to connect to gateway-mia2.goskope.com:443, err: 10065`
  * `Config System proxy configuration Not Detected , System proxy Count 0,Pac Server Host N/A`
* Parse npadebuglog.log
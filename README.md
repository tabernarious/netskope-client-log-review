# netskope-client-log-review
Parse and highlight information from Netskope Client Logs

## parse_nsdebuglog.py
PURPOSE: Parse nsdebuglog.log to highlight useful and important information

USAGE: python3 parse_nsdebuglog.py [custom path to nsdebuglog.log; default is /Library/Logs/Netskope/nsdebuglog.log]

## Enhancement Requests
* List endpoint source IPs in use
  * `Tunneling flow from addr: 2603:9000:5d00:1c:fdf0:9da5:xxxx:xxxx:59136`
  * `Tunneling flow from addr: 192.168.4.xxx:57425`
  * `nsUtils Pref src ip 2603:9000:5d00:1c:fdf0:9da5:xxxx:xxxx, iface 5`
  * `nsUtils Pref src ip 172.1.xxx.xxx, iface 21`
* List Netskope POPs connected to
  * `nsTunnel DTLS SSL connected to the gslbgw server: gateway-iad2.goskope.com(163.116.146.35):443 successfully`
* List Operating system
  * `Config setting STA user agent: Windows NT 11.0 x64;Netskope ST Agent 111.0.0.1880;ID-PF4H9SYA`
* List Client versions
  * `Config setting STA user agent: Windows NT 11.0 x64;Netskope ST Agent 111.0.0.1880;ID-PF4H9SYA`
* List endpoint hostname
  * `Config setting STA user agent: hostname: this-pc-name`
* List users seen
  * `nsImpersonate Current user: UserFirst.Lastname`
* Other log lines
  * `nsTunnel DTLS disconnecting nsTunnel, context = NSTUNNEL_DISCONNECTED_BYUSER`
  * `nsTunnel DTLS nsssl_connect failed, err: -1`
  * `nsssl DTLS failed to connect to gateway-mia2.goskope.com:443, err: 10065`
  * `Config System proxy configuration Not Detected , System proxy Count 0,Pac Server Host N/A`

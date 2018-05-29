# snifferpy

Analysis network traffic with arp spoofing:
```
Options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface=INTERFACE
                        Interface of capture network traffic
  -g GATEWAY, --gateway=GATEWAY
                        Gateway IP of router device
  -t TARGET, --target=TARGET
                        Target IP of device for analysis
  -v VERBOSE, --verbose=VERBOSE
                        Verbose mode
												
Example: python3 sniffer.py -i wlp3s0 -t 192.168.1.9 -g 192.168.1.1

```

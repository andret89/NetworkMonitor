
# Monitoring the network traffic of a device on the LAN

NetworkMonitoring is a program for the acquisition and analysis of network traffic of a device located in a LAN, using arp spoofing techniques. The program is able to show DNS requests on the shell and statistics, obtained from TCP and UDP packets, on a web interface offered by the Chronograph application.

## Usage

```
Usage: sudo python3 NetworkMonitoring.py [-hv] [-i interface] [-g gateway] [-t target] 
```

access the web page http://localhost:8888 to see the statistics

Options:

- `-h`: Shows the usage.
- `-i`: interface of capture network traffic.
- `-t`: Target IP of device for analysis.
- `-g`: Gateway IP of router device.
- `-e`: ex: example of usage
- `-v`: Enable verbose mode.

> Ex: sudo python3 sniffer.py -i enp2s0 -t 192.168.1.3 -g 192.168.1.1

## Installation

To install, follow these instructions

```
sudo apt install python3-pip 
```

If you prefer to use a virtual environment

```
sudo apt install python3-venv
python3 -m venv venv
source venv/bin/activate
```

To install dependencies
```
sudo pip3 install -r requirements.txt
```
To install database tools: **Influxdb**, **chronograf**:

visit https://portal.influxdata.com/downloads`

Start the services:
```
service influxdb start
service chronograf start
```

Finally, copy the chronograf-v1.db file to /var/lib/chronograf/ to import dashboard settings
PS: for correct operation make sure that the TCP port of influxdb is 8086
The software was developed for linux only and tested on debian based distro: 
linux mint 18.3 and ubuntu 18.04.

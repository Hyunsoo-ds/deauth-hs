# deauth-hs
802.11 deauth-attack tool using pcap

How to use
```
make
sudo ./airodump {interface name} {target AP's SSID} {target Station's SSID(Optional)}

If target Station's SSID won't be specified, deauth-attack will go broadcast
```

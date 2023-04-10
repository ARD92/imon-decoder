# Inline monitoring decoder 

This is an app to decode inline monitoring packets to view GTP tunneled packets. This will offer visibility into the flows encapsulated within GTP headers. The existing feature of Junos where in, if any GTP-U packets arrive, inline jflow would provide flow visibility only on the outer IP header. However there are IPv4 or IPv6 packets encapsulated within GTP headers. In order to obtain flow information, we can leverage inline monitoring which copies the original GTP packet into the data link layer field. 
This decodes the data link layer field and offer visibility into the exact flow. 

More information on inline monitoring can be read on [official documentation ](https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/topic-map/inline-monitoring-services-configuration.html)

## Necessary configuration needed on Junos 
```
set chassis fpc 0 pic 0 inline-services bandwidth 1g

set services inline-monitoring template GTP-1 template-refresh-rate 10
set services inline-monitoring template GTP-1 observation-domain-id 1
set services inline-monitoring template GTP-1 template-id 1024
set services inline-monitoring template GTP-1 primary-data-record-fields direction
set services inline-monitoring template GTP-1 primary-data-record-fields datalink-frame-size
set services inline-monitoring template GTP-1 primary-data-record-fields cpid-ingress-interface-index
set services inline-monitoring template GTP-1 primary-data-record-fields cpid-egress-interface-index
set services inline-monitoring instance GTP-1 template-name GTP-1
set services inline-monitoring instance GTP-1 collector COLLECTOR-2 source-address 30.1.1.1
set services inline-monitoring instance GTP-1 collector COLLECTOR-2 destination-address 30.1.1.2
set services inline-monitoring instance GTP-1 collector COLLECTOR-2 destination-port 1000
set services inline-monitoring instance GTP-1 collector COLLECTOR-2 sampling-rate 1

set interfaces ge-0/0/0 passive-monitor-mode
set interfaces ge-0/0/0 unit 0 family inet filter input GTPv4
set interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/30

set firewall family inet filter GTPv4 term teid-all then count GTP-1
set firewall family inet filter GTPv4 term teid-all then inline-monitoring-instance GTP-1
set firewall family inet filter GTPv4 term teid-all then accept
```

## Notes
- Sampling rate can be varied. I chose 1 for testing but having 1-1 sampling can cause performance issues
- App written as a prototype, do not expect performance if using this app 
- currently only v4 in v4 packets work 

## Usage 
```
./imon-decoder -i <interface which receives ipfix pkts>
```

## Captures

```
bash-5.1# ./imon-decoder -i pkt4

received ipfix packet...
Decoding IPFIX packet...
received template packet ....

received ipfix packet...
Decoding IPFIX packet...
Unable to decode Ipfix Packet...

======== Flow data ============
EgressIntf:  10000000
IngressIntf:  1800015a
Direction:  00
DataLinkSize:  99
============ GTP Layer =============
TEID:  3000
InnerSourceAddr :  10.1.1.2
InnerDestAddr :  10.1.1.1
InnerSourcePort :  1222
InnerDestPort :  1518
InnerProtocol :  6
----------
``` 

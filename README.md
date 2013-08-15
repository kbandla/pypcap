# pypcap

Python/C bindings for the libpcap library.
Most of the functions are 1:1 mapped to the libpcap library.

## Example 1

```python
>>> import pypcap
>>> pypcap.pcap_lookupdev()
'fw0'
>>> pypcap.pcap_findalldevs()
['fw0', 'en0', 'utun0', 'en1', 'p2p0']
>>> pypcap.pcap_lookupnet('en1')
('192.168.1.10', '255.255.252.0')
>>> pypcap.pcap_lib_version()
'libpcap version 1.1.1'
```

## Example 2

```python
from pypcap, dpkt
pc = pcap()
x.pcap_create( 'en1' )
x.pcap_set_buffer_size( 1000 )
x.pcap_set_snaplen( 576 )
x.pcap_set_timeout( 512 )
x.pcap_set_promisc( 1 )
x.pcap_activate()
x.pcap_compile( 'udp' )

def pcap_callback(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)
    for qd in dns.qd:
        print qd.name

x.pcap_set_callback(pcap_callback)
x.pcap_loop()
```

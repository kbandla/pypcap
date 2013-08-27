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
from pypcap import pcap
import dpkt
x = pcap()
x.pcap_create( 'eth0' )
x.pcap_set_promisc( True )
x.pcap_activate()
x.pcap_compile( 'udp' )

def pcap_callback(pkt):
    # do stuff with packet
    eth = dpkt.ethernet.Ethernet(pkt)

x.pcap_set_callback(pcap_callback)
x.pcap_loop()
```

## Notes
### Linux
* On 64-bit Linux, the buffer's size should be least the snap length set for the handle in use. If not, you will end up with a "can't mmap rx ring: Invalid argument" [error](http://stackoverflow.com/questions/11397367/issue-in-pcap-set-buffer-size). 
* On Linux, root privileges are required even for module functions (pcap_lookupdev, etc )

### Research
* Designing an iterator on top of pcap_next() is easy, but the fact that it calls pcap_dispatch() with cnt=1 seems like a performance drag compared to pcap_loop/callback. Needs more investigation.
* Read more about GIL implementaion and thread-state for C Extensions

### Remaining Work
* Make it thread-safe
* GIL / thread-state
* Reference counting
* Add pcap_dump routines
* Add iterators for pcap_next
* Add unittests
* Add timestamp to pcap_loop callback
* WIN32 Support

### License
See LICENSE file

### Requires
* Python 2.5 or later
* python-dev
* libpcap-dev

### Tested on
* OSX 10.8  - x86_64
* Linux     - x86_64
* Not tested on 32bit Linux/OSX, but should work

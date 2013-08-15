# pypcap test file

import pypcap
import dpkt

# module functions
print 'lookupdev = ', pypcap.pcap_lookupdev()
print 'findalldevs = ', pypcap.pcap_findalldevs()
print 'pcap_lookupnet(eth0) = ', pypcap.pcap_lookupnet('eth0')

# create a pcap
x = pypcap.pcap()
print 'pcap_create = ', x.pcap_create('eth0')
print 'interface = ', x.interface
print 'pcap_set_buffer_size = ', x.pcap_set_buffer_size(1000)
print 'pcap_set_snaplen = ', x.pcap_set_snaplen(576)
print 'pcap_set_timeout = ', x.pcap_set_timeout(512)
print 'pcap_set_promisc = ', x.pcap_set_promisc(0)
print 'pcap_activate = ', x.pcap_activate()
print 'pcap_compile = ', x.pcap_compile('udp port 53')

def pcap_callback(pkt):
    # do stuff with the packet
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)
    for qd in dns.qd:
        print qd.name

print 'pcap_set_callback = ', x.pcap_set_callback(pcap_callback)
print 'pcap_loop = ', x.pcap_loop()

# pypcap unittests
import os
import sys
import glob
import unittest

sys.path.insert(0, glob.glob('build/lib.*')[0])
import pypcap

try:
    import dpkt
except Exception,e:
    dpkt = False

class ModuleTests(unittest.TestCase):
    '''
    Various tests on the module-level functionality 
    '''
    def setUp(self):
        pass

    def test0_import(self):
        try:
            import pypcap
        except Exception,e:
            self.assertTrue(False, 'Could not import pypcap : %s'%(e))

    def test1_pcap_lib_version(self):
        ver = pypcap.pcap_lib_version()
        self.assertTrue( ver, 'Could not get libpcap version')

    def test2_pcap_findalldevs(self):
        devs = pypcap.pcap_findalldevs()
        self.assertTrue( devs, 'Could not get devices')
    
    def test3_pcap_lookupdev(self):
        devs = pypcap.pcap_findalldevs()
        dev = pypcap.pcap_lookupdev()
        self.assertTrue( dev in devs , 'Could not find device in list of available devices %s'%(','.join(devs)))

    def test4_pcap_lookupnet(self):
        devs = pypcap.pcap_findalldevs()
        dev = pypcap.pcap_lookupdev()
        details = None
        for dev in devs:
            try:
                details = pypcap.pcap_lookupnet( dev )
                break
            except Exception,e:
                pass
        self.assertTrue( details, 'Could not lookup network details for any interface (%s)'%(','.join(devs)))
    
class ClassTests(unittest.TestCase):
    def setUp(self):
        self.pcap = pypcap.pcap()
        devs = pypcap.pcap_findalldevs()
        for dev in devs:
            try:
                pypcap.pcap_lookupnet( dev )
                break
            except Exception,e:
                pass

        print 'Found %s interface, and it has network'%( dev )
        pcap = self.pcap.pcap_create(dev)
        self.assertTrue( pcap, 'Error creating a pcap object')


if __name__ == '__main__':
    unittest.main()
    exit()

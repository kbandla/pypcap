/*
    A pure Python/C binding for libpcap
    Copyright (C) Kiran Bandla <kbandla@in2void.com>
 */

#include <Python.h>

PyDoc_STRVAR(pcap_lib_version__doc__,
        "pcap_lib_version() -> s\n\n"
        "get the version information for libpcap\n"
        );

PyDoc_STRVAR(pcap_create__doc__,
        "pcap_create( interface ) -> bool\n\n"
        "Create a live capture handle\n"
        "Raises an exception with an appropriate message in case of errors\n"
        "Returns a True if it was successful\n"
        "\n"
        );

PyDoc_STRVAR(pcap_open_offline__doc__,
        "pcap_open_offline( filepath ) -> bool\n\n"
        "open a saved capture file for reading"
        );

PyDoc_STRVAR(pcap_lookupdev__doc__,
        "pcap_lookupdev() -> s\n\n"
        "Find the default device on which to capture\n"
        );

PyDoc_STRVAR(pcap_findalldevs__doc__,
        "pcap_findalldevs() -> list\n\n"
        "Get a list of capture devices\n"
        "Raises an exception with an appropriate message in case of errors\n"
        );

PyDoc_STRVAR(pcap_lookupnet__doc__,
        "pcap_lookupnet( interface ) -> (ip, netmask)\n\n"
        "find the IPv4 network number and netmask for a device\n"
        "Raises an exception with an appropriate message in case of errors\n"
        );

PyDoc_STRVAR(pcap_datalink__doc__,
        "pcap_datalink() -> int\n\n"
        "Get the link-layer header type\n"
        );

PyDoc_STRVAR(pcap_datalink_val_to_name__doc__,
        "pcap_datalink_val_to_name() -> s\n\n"
        "get a name or description for a link-layer header type value\n"
        );

PyDoc_STRVAR(pcap_datalink_val_to_description__doc__,
        "pcap_datalink_val_to_description() -> s\n\n"
        "get a name or description for a link-layer header type value\n"
        );

PyDoc_STRVAR(pcap_set_buffer_size__doc__,
        "pcap_set_buffer_size( size ) -> bool\n\n"
        "Set the buffer size for a not-yet-activated capture handle\n"
        );

PyDoc_STRVAR(pcap_set_snaplen__doc__,
        "pcap_set_snaplen( len ) -> bool\n\n"
        "Set the snapshot length for a not-yet-activated capture handle\n"
        );

PyDoc_STRVAR(pcap_set_timeout__doc__,
        "pcap_set_timeout( timeout ) -> bool\n\n"
        "Set the read timeout for a not-yet-activated capture handle\n"
        );

PyDoc_STRVAR(pcap_set_promisc__doc__,
        "pcap_set_promisc( bool ) -> bool\n\n"
        "Set promiscuous mode for a not-yet-activated capture handle"
        );

PyDoc_STRVAR(pcap_activate__doc__,
        "pcap_activate() -> bool\n\n"
        "Activate a capture handle\n"
        "Raises an exception with an appropriate message in case of errors\n"
        );

PyDoc_STRVAR(pcap_compile__doc__,
        "pcap_compile( capture_filter ) --> bool\n\n"
        "Compile a filter expression\n"
        );

PyDoc_STRVAR(pcap_set_callback__doc__,
        "pcap_set_callback( func ) -> bool\n\n"
        "Set the callback which will be used by pcap_loop\n"
        "Raises and exception with an appropriate message\n"
        "Returns a True if it was successful\n"
        );

PyDoc_STRVAR(pcap_loop__doc__,
        "pcap_loop( [count], [uid] ) -> bool\n\n"
        "Starts the pcap capture loop\n"
        "@count = Number of packets to capture. Default = unlimited\n"
        "@uid = UID of the user to run as. Ex: nobody's UID \n"
        "\n"
        "For each packet captured, it will call the callback function \n"
        "that was set via pcap_set_callback()\n"
        "For the UID, somehting like 'pwd.getpwnam('nobody').pw_uid)' can be used\n"
        );

PyDoc_STRVAR(pcap_sendpacket__doc__, 
        "pcap_sendpacket( packet ) -> bool\n\n"
        "Transmit a packet\n"
        "Returns True if the packet is succesfully sent\n"
        "Raises an exception otherwise.\n"
        "The MAC CRC doesn't need to be included, because it is transparently calculated\n"
        "and added by the network interface driver.\n\n"
        "Also see pcap_inject()\n"
        );

PyDoc_STRVAR(pcap_can_set_rfmon__doc__,
        "pcap_can_set_rfmon() -> bool\n\n"
        "Check whether monitor mode can be set for a not-yet-activated capture handle\n"
        );

PyDoc_STRVAR(pcap_set_rfmon__doc__,
        "pcap_set_rfmon( bool ) -> bool\n\n"
        "Set monitor mode for a not-yet-activated capture handle\n"
        "Returns True if sucessful else returns False\n"
        );


PyDoc_STRVAR(pcap_list_datalinks__doc__,
        "pcap_list_datalinks() -> list\n\n"
        "Get a list of link-layer header types supported by a capture device\n"
        );

PyDoc_STRVAR(pcap_snapshot__doc__,
        "pcap_snapshot() -> int\n\n"
        "get the snapshot length\n"
        );

PyDoc_STRVAR(pcap_datalink_name_to_val__doc__,
        "pcap_datalink_name_to_val( name ) -> int\n\n"
        "get  the  link-layer header type value corresponding to a header type name"
        );

PyDoc_STRVAR(pcap_stats__doc__,
        "pcap_stats() -> dict\n\n"
        "get capture statistics\n"
        "ps_recv: number of packets received\n"
        "ps_drop: number of packets dropped because there was no room in the operating system's buffer when they arrived, because packets weren't being read fast enoug\n"
        "ps_ifdrop: number of packets dropped by the network interface or its driver\n"
        "bs_capt: number of packets captured (Win32)\n"
        );

#ifdef Win32
PyDoc_STRVAR(pcap_stats_ex__doc__,
        "pcap_stats_ex() -> dict\n\n"
        "This is only supported on Windows. Untested\n"
        );
#endif

/*
    A pure Python/C binding for libpcap
    pypcap.c : implementation
    Copyright (C) Kiran Bandla <kbandla@in2void.com>
 */

#include <Python.h>
#include <structmember.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "pypcap.h"
#include "docs.h"

static PyObject *PyPcap_Error;

PyObject *arglist;
PyObject *result;
int pcap_offset;
char pcap_errbuf[PCAP_ERRBUF_SIZE];
struct timeval pktts;
double tsdouble;

static void
pypcap_dealloc(PyPcapObject* self)
{
    Py_XDECREF(self->interface);
    if(self->pcap)
        pcap_close(self->pcap);
    if(self->pcap_dumper)
        pcap_dump_close(self->pcap_dumper);
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject*
pypcap_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyPcapObject *self;
    self = (PyPcapObject*)type->tp_alloc(type, 0);
    self->pcap = NULL;
    self->pcap_dumper = NULL;
    self->config = PyDict_New();
    self->interface = Py_None;
    self->callback = Py_None;
    return (PyObject *)self;
}

static int
pypcap_init(PyPcapObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *interface=NULL;
    static char *kwlist[] = {"interface", NULL};
    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist, &interface))
        return -1; 

    if (interface) {
#ifdef DEBUG
        printf("init got an interface\n");
#endif
        //save interface
        self->interface = interface;
        Py_XINCREF(self->interface);
        if(PyDict_SetItem(self->config, PyString_FromString("interface"), self->interface)){
            PyErr_SetString(PyPcap_Error, "error setting config dict item buffer_size");
            return -1;
        }
        Py_XINCREF(self->interface);
    } else {
#ifdef DEBUG
        printf("init did not get an interface\n");
#endif
    }
    return 0;
}

static PyObject*
pypcap_pcap_lib_version(PyObject *self, PyObject *args)
{
    PyObject *version;
    version = PyString_FromString(pcap_lib_version());
    return version;
}

static PyObject*
pypcap_pcap_create(PyPcapObject *self, PyObject *args)
{
    char *interface=NULL;
    if(self->interface == Py_None){
#ifdef DEBUG
        printf("No previous definitions for interface\n");
#endif
        if (!PyArg_ParseTuple(args, "s", &interface)){
            return NULL;
        }
#ifdef DEBUG
        printf("pcap_create got an interface\n");
#endif
        // save interface
        self->interface = PyString_FromString( interface );
        Py_XINCREF(self->interface);
        if(PyDict_SetItem(self->config, PyString_FromString("interface"), self->interface)){
            PyErr_SetString(PyPcap_Error, "error setting config dict item buffer_size");
            return NULL;
        }
        Py_XINCREF(self->interface);
    } else {
#ifdef DEBUG
        printf("Have a previous definition of interface\n");
#endif
        interface = PyString_AsString(self->interface);
    }

    if(getuid()!= 0){
        PyErr_SetString(PyPcap_Error, "Sniffing requires root privileges");
        return NULL; 
    }

    self->pcap = pcap_create( interface, pcap_errbuf );

    if(self->pcap==NULL){
       PyErr_SetString(PyPcap_Error, pcap_errbuf);
        return NULL; 
    }
    Py_XINCREF(self->pcap);
    Py_RETURN_TRUE;
}

static PyObject*
pypcap_pcap_open_offline(PyPcapObject *self, PyObject *args)
{
    char *filepath=NULL;
    if (!PyArg_ParseTuple(args, "s", &filepath)){
        return NULL;
    }
#ifdef DEBUG
    printf("opening offline file : %s\n", filepath);
#endif
    self->pcap = pcap_open_offline( filepath, pcap_errbuf);

    if(self->pcap==NULL){
        PyErr_SetString(PyPcap_Error, pcap_errbuf);
        return NULL; 
    }
    Py_XINCREF(self->pcap);
    Py_RETURN_TRUE;

}

static PyObject*
pypcap_pcap_dump_open(PyPcapObject *self, PyObject *args)
{
    char *filepath = NULL;
    if (!PyArg_ParseTuple(args, "s", &filepath)){
        return NULL;
    }
#ifdef DEBUG
    printf("pcap_dump file : %s\n", filepath);
#endif
    self->pcap_dumper = pcap_dump_open(self->pcap, filepath);
    if(self->pcap_dumper == NULL){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    } else {
        Py_XINCREF( self->pcap_dumper);
    }
    if(PyDict_SetItem(self->config, PyString_FromString("dumpfile"), PyString_FromString(filepath))){
        PyErr_SetString(PyPcap_Error, "error setting config dict item dumpfile");
        return NULL;
    }
    Py_RETURN_TRUE;
}

void pcap_dumper_callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    PyPcapObject *self;
    self = (PyPcapObject*)user;
    if(PyErr_CheckSignals()){
        pcap_breakloop(self->pcap);
    }
    pcap_dump((u_char*) self->pcap_dumper, pkthdr, packet);
}

static PyObject*
pypcap_pcap_dump(PyPcapObject *self, PyObject *args, PyObject *kwds){
    int capture_count = -1;
    int euid = 0;
    int ret;
    static char *kwlist[] = {"count", "uid", NULL};
    PyCHECK_SELF;
    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwlist, &capture_count, &euid)){
        PyErr_SetString(PyPcap_Error, "Error setting capture_count");
        return NULL;
    }
    if(euid){
        if (seteuid(euid) == -1){
            PyErr_SetString(PyPcap_Error, "Error dropping privileges");
            return NULL;
        }
    }
#ifdef DEBUG
    printf("Starting pcap_loop for packet capture to file :\n" );
    printf("\tcount = %d | uid = %d\n", capture_count, uid);
#endif
    ret = pcap_loop(self->pcap, capture_count, pcap_dumper_callback, (u_char*) self);
    if(ret == -1) {
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL;
    }
    Py_RETURN_TRUE;
}

static PyObject*
pypcap_lookupdev(PyObject *self, PyObject *args)
{
    PyObject *pcap_device;
    char *device=NULL;
    device = pcap_lookupdev(pcap_errbuf);
    pcap_device = PyString_FromString( device );
    return pcap_device;
}

static PyObject*
pypcap_pcap_findalldevs(PyObject *self, PyObject *args)
{
    PyObject *interfacesL = PyList_New(0);  // list of interfaces
    PyObject *tmp;
    
    pcap_if_t *interfaces = NULL;
    if( pcap_findalldevs(&interfaces, pcap_errbuf) != 0){
        PyErr_SetString(PyPcap_Error, pcap_errbuf);
        return NULL; 
    } 
    if(!interfaces){
        PyErr_SetString(PyPcap_Error, "Could not get interface details");
        return NULL; 
    }
    while(interfaces->next != NULL){
        tmp = PyString_FromString( interfaces->name );
        if(PyList_Append(interfacesL, tmp)){
            PyErr_SetString(PyPcap_Error, "Error append to list of interfaces");
            return NULL; 
        }

        interfaces = interfaces->next;
    }
    return interfacesL;
}

static PyObject*
pypcap_pcap_lookupnet(PyObject *self, PyObject *args)
{
    PyObject *network = PyTuple_New(2);
    bpf_u_int32 netaddr =0, mask=0;
    struct in_addr ipaddr, maskaddr;
    char ipaddr_text[INET_ADDRSTRLEN], mask_text[INET_ADDRSTRLEN];
    char *interface;

    if (!PyArg_ParseTuple(args, "s", &interface)){
        return NULL;
    }

#ifdef DEBUG
    printf("lookupnet %s\n", interface);
#endif

    if (pcap_lookupnet(interface, &netaddr, &mask,pcap_errbuf) != 0){
        PyErr_SetString(PyPcap_Error, pcap_errbuf);
        return NULL; 
    } 
    
    ipaddr.s_addr = netaddr;
    maskaddr.s_addr = mask;
    if(!inet_ntop(AF_INET, &ipaddr, ipaddr_text, INET_ADDRSTRLEN)){
        PyErr_SetString(PyPcap_Error, "inet_ntop error");
        return NULL;
    }
    if(!inet_ntop(AF_INET, &maskaddr, mask_text, INET_ADDRSTRLEN)){
        PyErr_SetString(PyPcap_Error, "inet_ntop error");
        return NULL;
    }
    
    if(PyTuple_SetItem(network, 0, PyString_FromString(ipaddr_text))){
        PyErr_SetString(PyPcap_Error, "error setting tuple item(0)");
        return NULL;
    }
    if(PyTuple_SetItem(network, 1, PyString_FromString(mask_text))){
        PyErr_SetString(PyPcap_Error, "error setting tuple item(1)");
        return NULL;
    }

    return network;
    
}

static PyObject*
pypcap_pcap_datalink(PyPcapObject *self)
{
    PyObject *linklayer;
    PyCHECK_SELF;
    linklayer = PyInt_FromLong((long)pcap_datalink(self->pcap));
    return linklayer;
}

static PyObject*
pypcap_pcap_datalink_name_to_val(PyObject *self, PyObject *args)
{
    char *linkName = NULL;
    PyObject *linktype;
    int linkType;
    if (!PyArg_ParseTuple(args, "s", &linkName)){
        return NULL;
    }
#ifdef DEBUG
    printf("datalink_name : %s\n", linkName);
#endif
    linkType = pcap_datalink_name_to_val(linkName);
    
    if(linkType == -1){
        PyErr_SetString(PyPcap_Error, "Error translating link name to value");
        return NULL;
    }

    linktype = PyInt_FromLong((long)linkType);
    return linktype;
}

static PyObject*
pypcap_pcap_datalink_val_to_name(PyPcapObject *self)
{
    PyObject *link_name;
    PyCHECK_SELF;
    link_name = PyString_FromString(pcap_datalink_val_to_name( pcap_datalink(self->pcap)) );
    return link_name;
}

static PyObject*
pypcap_pcap_datalink_val_to_description(PyPcapObject *self)
{
    PyObject *link_description;
    PyCHECK_SELF;
    link_description = PyString_FromString( pcap_datalink_val_to_description( pcap_datalink(self->pcap)) );
    return link_description;
}

static PyObject*
pypcap_pcap_set_buffer_size(PyPcapObject *self, PyObject *args)
{
    int PCAP_CAPTURE_BUFFER;
    PyCHECK_SELF;
    if (!PyArg_ParseTuple(args, "i", &PCAP_CAPTURE_BUFFER)){
        return NULL;
    }
    if(pcap_set_buffer_size(self->pcap, PCAP_CAPTURE_BUFFER) !=0 ){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    if(PyDict_SetItem(self->config, PyString_FromString("buffer_size"), PyInt_FromLong(PCAP_CAPTURE_BUFFER))){
        PyErr_SetString(PyPcap_Error, "error setting config dict item buffer_size");
        return NULL;
    }

    Py_RETURN_TRUE;
}

static PyObject*
pypcap_pcap_set_snaplen(PyPcapObject *self, PyObject *args)
{
    int PCAP_SNAPLEN;
    PyCHECK_SELF;
    if (!PyArg_ParseTuple(args, "i", &PCAP_SNAPLEN)){
        return NULL;
    }
    if(pcap_set_snaplen(self->pcap, PCAP_SNAPLEN) !=0 ){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    if(PyDict_SetItem(self->config, PyString_FromString("snaplen"), PyInt_FromLong(PCAP_SNAPLEN))){
        PyErr_SetString(PyPcap_Error, "error setting config dict item snaplen");
        return NULL;
    }
    Py_RETURN_TRUE;

}

static PyObject*
pypcap_pcap_set_timeout(PyPcapObject *self, PyObject *args)
{
    int PCAP_READ_TIMEOUT;
    PyCHECK_SELF;
    if (!PyArg_ParseTuple(args, "i", &PCAP_READ_TIMEOUT)){
        return NULL;
    }
    if(pcap_set_timeout(self->pcap, PCAP_READ_TIMEOUT) !=0 ){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    if(PyDict_SetItem(self->config, PyString_FromString("timeout"), PyInt_FromLong(PCAP_READ_TIMEOUT))){
        PyErr_SetString(PyPcap_Error, "error setting config dict item timeout");
        return NULL;
    }
    Py_RETURN_TRUE;

}

static PyObject*
pypcap_pcap_set_promisc(PyPcapObject *self, PyObject *args)
{
    PyObject *input;
    int PROMISCUOUS;
    PyCHECK_SELF;
    if (!PyArg_ParseTuple(args, "O", &input)){
        PyErr_SetString(PyPcap_Error, "Error assigning to input");
        return NULL;
    }
    PROMISCUOUS = PyObject_IsTrue(input);
    if(pcap_set_promisc(self->pcap, PROMISCUOUS) !=0){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    if(PyDict_SetItem(self->config, PyString_FromString("promisc"), input)){
        PyErr_SetString(PyPcap_Error, "error setting config dict item promisc");
        return NULL;
    }
    Py_RETURN_TRUE;
}

static PyObject*
pypcap_pcap_activate(PyPcapObject *self)
{
    PyCHECK_SELF;
    if(pcap_activate(self->pcap) !=0 ){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    if(PyDict_SetItem(self->config, PyString_FromString("activated"), Py_True)){
        PyErr_SetString(PyPcap_Error, "error setting config dict item activated");
        return NULL;
    }
    Py_RETURN_TRUE;
}

static PyObject*
pypcap_pcap_compile(PyPcapObject *self, PyObject *args)
{
    char *capture_interface = NULL;
    char *capture_filter=NULL;
    bpf_u_int32 netaddr =0, mask=0;
    struct bpf_program filter ;
    /*
    // we need pcap_dlinkoffset form pcaputils.c
    if ( (pcap_offset = pcap_dlinkoffset(self->pcap)) < 0){
        //error
        Py_RETURN_FALSE;
    }
    */

    PyCHECK_SELF;
    if (!PyArg_ParseTuple(args, "s", &capture_filter)){
        PyErr_SetString(PyPcap_Error, "Need a capture filter" );
        return NULL;
    }
    
    if (!self->interface){
        PyErr_SetString(PyPcap_Error, "Need a capture interface to listen on");
        return NULL; 
    }
    capture_interface = PyString_AsString( self->interface);
    if (pcap_lookupnet(capture_interface,&netaddr,&mask,pcap_errbuf) != 0){
        /* 
           This could happen if the interface is not configured
           Set netmask to PCAP_NETMASK_UNKNOWN instead and proceed
       */
        mask = PCAP_NETMASK_UNKNOWN;
#ifdef DEBUG
        printf("Could not get IPv4 information for the interface.\n");
#endif
    }

    if (pcap_compile(self->pcap,&filter, (char *)capture_filter, 1, mask) !=0){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }

    if(pcap_setfilter(self->pcap,&filter) !=0){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }

    if(PyDict_SetItem(self->config, PyString_FromString("filter"), PyString_FromString(capture_filter))){
        PyErr_SetString(PyPcap_Error, "error setting config dict item buffer_size");
        return NULL;
    }
    Py_RETURN_TRUE;
}


void handle_pkt(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    PyPcapObject *self;
    self = (PyPcapObject*)user;
    if(PyErr_CheckSignals()){
        pcap_breakloop(self->pcap);
    }
    pktts = pkthdr->ts;
    tsdouble = pktts.tv_sec + pktts.tv_usec / 1000000.0;
    arglist = Py_BuildValue("s#d", packet, pkthdr->len, tsdouble);

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();
    result = PyObject_CallObject( self->callback, arglist);
    if(result == NULL){
        pcap_breakloop(self->pcap);
        PyErr_SetString(PyExc_TypeError, "Something went wrong");
    }
    PyGILState_Release(gstate);
    Py_DECREF(arglist);
}

static PyObject*
pypcap_pcap_set_callback(PyPcapObject *self, PyObject *args)
{
    PyCHECK_SELF;
    if (PyArg_ParseTuple(args, "O:set_callback", &self->callback)) {
        if (!PyCallable_Check(self->callback)) {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
            return NULL;
        }
        Py_XINCREF(self->callback);
    }
    if(PyDict_SetItem(self->config, PyString_FromString("callback"), self->callback)){
        PyErr_SetString(PyPcap_Error, "error setting config dict item callback");
        return NULL;
    }
    Py_RETURN_TRUE;
}

static PyObject*
pypcap_pcap_loop(PyPcapObject *self, PyObject *args, PyObject *kwds)
{
    int capture_count = -1;
    int euid = 0;
    int ret;
    static char *kwlist[] = {"count", "uid", NULL};
    PyCHECK_SELF;
    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwlist, &capture_count, &euid)){
        PyErr_SetString(PyPcap_Error, "Error setting capture_count");
        return NULL;
    }
    if(euid){
        if (seteuid(euid) == -1){
            PyErr_SetString(PyPcap_Error, "Error dropping privileges");
            return NULL;
        }
    }
    ret = pcap_loop(self->pcap, capture_count, handle_pkt, (u_char*) self);
    if(ret == -1) {
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL;
    }
    Py_RETURN_TRUE;
}

static PyObject*
pypcap_pcap_sendpacket(PyPcapObject *self, PyObject *args)
{
    u_char *buffer;
    int length;
    PyCHECK_SELF;
    if (!PyArg_ParseTuple(args, "s#", &buffer, &length)){
        PyErr_SetString(PyPcap_Error, "Error assigning to inputString object");
        return NULL;
    }
    
    if(pcap_sendpacket(self->pcap, buffer, length) == -1){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL;
    }
    Py_RETURN_TRUE;
}

static PyObject*
pypcap_pcap_can_set_rfmon(PyPcapObject *self)
{
    PyCHECK_SELF;
    switch( pcap_can_set_rfmon(self->pcap) ){
            case 0:
                Py_RETURN_FALSE;
            case 1:
                Py_RETURN_TRUE;
            case PCAP_ERROR_NO_SUCH_DEVICE:
                PyErr_SetString(PyPcap_Error, "device  specified doesn't exist");
                return NULL;
            case PCAP_ERROR_ACTIVATED:
                PyErr_SetString(PyPcap_Error, "capture handle has been activated");
                return NULL;
            case PCAP_ERROR:
                PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
                return NULL;
            default:
                PyErr_SetString(PyPcap_Error, "Unknown error");
                return NULL;
    }
}

static PyObject*
pypcap_pcap_set_rfmon(PyPcapObject *self, PyObject *args)
{
    PyObject *input;
    int rfmon;
    PyCHECK_SELF;
    if (!PyArg_ParseTuple(args, "O", &input)){
        PyErr_SetString(PyPcap_Error, "Error assigning to input");
        return NULL;
    }
    rfmon = PyObject_IsTrue(input);
    if( rfmon == -1 ){
        PyErr_SetString(PyPcap_Error, "Invalid input object");
        return NULL;
    }

    switch(pcap_set_rfmon(self->pcap, rfmon)){
        case 0:
            if(PyDict_SetItem(self->config, PyString_FromString("rfmon"), Py_True)){
                PyErr_SetString(PyPcap_Error, "error setting config dict item rfmon");
                return NULL;
            }
            Py_RETURN_TRUE;
        case PCAP_ERROR_ACTIVATED:
            PyErr_SetString(PyPcap_Error, "capture handle has been activated");
            return NULL;
        default:
            Py_RETURN_FALSE;
    }

}

static PyObject*
pypcap_pcap_list_datalinks(PyPcapObject *self)
{
    PyObject *datalinksL = PyList_New(0);
    PyObject *tmp;
    int *dlt_buf;
    int i,n;
    PyCHECK_SELF;
    n = pcap_list_datalinks(self->pcap, &dlt_buf);
    if (n == -1){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL;
    }

    for(i=0; i<n; i++){
        tmp = PyInt_FromLong((long)dlt_buf[i]);
        if(PyList_Append(datalinksL, tmp)){
            pcap_free_datalinks(dlt_buf);
            PyErr_SetString(PyPcap_Error, "Error append to list of datalinks");
            return NULL; 
        }
    }
    pcap_free_datalinks(dlt_buf);
    return datalinksL;
}

static PyObject*
pypcap_pcap_snapshot(PyPcapObject *self, PyObject *args)
{
    PyObject *tmp;
    PyCHECK_SELF;
    tmp = PyInt_FromLong((long)pcap_snapshot(self->pcap));
    return tmp;
}

static PyObject*
pypcap_pcap_stats(PyPcapObject *self)
{
    PyObject *stats = PyDict_New();
    struct pcap_stat ps ;
    PyCHECK_SELF;
    if(pcap_stats(self->pcap, &ps) == -1){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL;
    }

    if(PyDict_SetItem(stats, PyString_FromString("ps_recv"), PyInt_FromLong(ps.ps_recv))){
        PyErr_SetString(PyPcap_Error, "error setting dict item ps_recv");
        return NULL;
    }
    if(PyDict_SetItem(stats, PyString_FromString("ps_drop"), PyInt_FromLong(ps.ps_drop))){
        PyErr_SetString(PyPcap_Error, "error setting dict item ps_drop");
        return NULL;
    }
    if(PyDict_SetItem(stats, PyString_FromString("ps_ifdrop"), PyInt_FromLong(ps.ps_ifdrop))){
        PyErr_SetString(PyPcap_Error, "error setting dict item ps_drop");
        return NULL;
    }
#ifdef WIN32
    if(PyDict_SetItem(stats, PyString_FromString("bs_capt"), PyInt_FromLong(ps.bs_capt))){
        PyErr_SetString(PyPcap_Error, "error setting dict item bs_capt");
        return NULL;
    }
#endif

    Py_XINCREF(stats);
    return stats;

}

#ifdef WIN32
static PyObject*
pypcap_pcap_stats_ex(PyPcapObject *self){
    PyObject *stats = PyDict_New();
    struct pcap_stat_ex ps;
    PyCHECK_SELF;
    if(pcap_stats_ex(self->pcap, &ps) == -1){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL;
    }

    if(PyDict_SetItem(stats, PyString_FromString("rx_packets"), PyInt_FromLong(ps.rx_packets))){
        PyErr_SetString(PyPcap_Error, "error setting dict item rx_packets");
        return NULL;
    }

    Py_XINCREF(stats);
    return stats;
}
#endif

static PyMemberDef PyPcap_Members[] = {
    {"config", T_OBJECT_EX, offsetof(PyPcapObject, config), 0, "Capture config"},
    {"interface", T_OBJECT_EX, offsetof(PyPcapObject, interface), 0, "Interface name"},
    {"callback", T_OBJECT_EX, offsetof(PyPcapObject, callback), 0, "Callback function"},
    {NULL}  /* Sentinel */
};

static PyMethodDef PyPcap_Methods[] = {
    {"pcap_create", (PyCFunction)pypcap_pcap_create, METH_VARARGS, pcap_create__doc__},
    {"pcap_open_offline", (PyCFunction)pypcap_pcap_open_offline, METH_VARARGS, pcap_open_offline__doc__},
    {"pcap_dump_open", (PyCFunction)pypcap_pcap_dump_open, METH_VARARGS, pcap_dump_open__doc__},
    {"pcap_dump", (PyCFunction)pypcap_pcap_dump, METH_VARARGS|METH_KEYWORDS, pcap_dump__doc__},
    {"pcap_datalink", (PyCFunction)pypcap_pcap_datalink, METH_VARARGS, pcap_datalink__doc__},
    {"pcap_datalink_val_to_name", (PyCFunction)pypcap_pcap_datalink_val_to_name, METH_VARARGS, pcap_datalink_val_to_name__doc__},
    {"pcap_datalink_val_to_description", (PyCFunction)pypcap_pcap_datalink_val_to_description, METH_VARARGS, pcap_datalink_val_to_description__doc__},
    {"pcap_set_buffer_size", (PyCFunction)pypcap_pcap_set_buffer_size, METH_VARARGS, pcap_set_buffer_size__doc__},
    {"pcap_set_snaplen", (PyCFunction)pypcap_pcap_set_snaplen, METH_VARARGS, pcap_set_snaplen__doc__},
    {"pcap_set_timeout", (PyCFunction)pypcap_pcap_set_timeout, METH_VARARGS, pcap_set_timeout__doc__},
    {"pcap_set_promisc", (PyCFunction)pypcap_pcap_set_promisc, METH_VARARGS, pcap_set_promisc__doc__},
    {"pcap_activate",       (PyCFunction)pypcap_pcap_activate,   METH_VARARGS, pcap_activate__doc__},
    {"pcap_compile",        (PyCFunction)pypcap_pcap_compile,    METH_VARARGS, pcap_compile__doc__},
    {"pcap_set_callback",   (PyCFunction)pypcap_pcap_set_callback, METH_VARARGS, pcap_set_callback__doc__},
    {"pcap_loop",           (PyCFunction)pypcap_pcap_loop,       METH_VARARGS|METH_KEYWORDS, pcap_loop__doc__},
    {"pcap_sendpacket",     (PyCFunction)pypcap_pcap_sendpacket, METH_VARARGS, pcap_sendpacket__doc__},
    {"pcap_set_rfmon",      (PyCFunction)pypcap_pcap_set_rfmon,  METH_VARARGS, pcap_set_rfmon__doc__},
    {"pcap_can_set_rfmon",  (PyCFunction)pypcap_pcap_can_set_rfmon, METH_VARARGS, pcap_can_set_rfmon__doc__},
    {"pcap_list_datalinks", (PyCFunction)pypcap_pcap_list_datalinks, METH_VARARGS, pcap_list_datalinks__doc__},
    {"pcap_snapshot", (PyCFunction)pypcap_pcap_snapshot, METH_VARARGS, pcap_snapshot__doc__},
    {"pcap_stats", (PyCFunction)pypcap_pcap_stats, METH_VARARGS, pcap_stats__doc__},
#ifdef Win32
    {"pcap_stats_ex", (PyCFunction)pypcap_pcap_stats_ex, METH_VARARGS, pcap_stats_ex__doc__},
#endif
    {NULL, NULL}  /* Sentinel */
};

static PyMethodDef module_methods[] = {
    // Some helper funtions
    {"pcap_datalink_name_to_val", pypcap_pcap_datalink_name_to_val, METH_VARARGS, pcap_datalink_name_to_val__doc__},
    {"pcap_lookupdev", pypcap_lookupdev, METH_VARARGS, pcap_lookupdev__doc__},
    {"pcap_findalldevs", pypcap_pcap_findalldevs, METH_VARARGS, pcap_findalldevs__doc__},
    {"pcap_lookupnet", pypcap_pcap_lookupnet, METH_VARARGS, pcap_lookupnet__doc__},
    {"pcap_lib_version", pypcap_pcap_lib_version, METH_VARARGS, pcap_lib_version__doc__},
    {NULL}  /* Sentinel */
};

static PyTypeObject PyPcapType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "pypcap.pypcap",           /*tp_name*/
    sizeof(PyPcapObject),      /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)pypcap_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Python/C API for libpcap",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    PyPcap_Methods,             /* tp_methods */
    PyPcap_Members,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)pypcap_init,      /* tp_init */
    0,                         /* tp_alloc */
    pypcap_new,                 /* tp_new */
};

#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC initpypcap(void){
    PyObject *pypcap;
    PyPcap_Error = PyErr_NewException("pcap.Error", NULL, NULL);
    Py_INCREF(PyPcap_Error);
#ifdef __linux__
    if(getuid()!= 0){
       PyErr_SetString(PyPcap_Error, "pypcap requires root privileges");
        return NULL; 
    }
#endif
    if (PyType_Ready(&PyPcapType) < 0)
        return;
    // 'pcap' module
    pypcap = Py_InitModule3("pypcap", module_methods, "C/Python bindings for libpcap");
    if( pypcap == NULL)
        return;
    Py_INCREF(&PyPcapType);
    PyModule_AddObject(pypcap, "pcap", (PyObject *)&PyPcapType);
    PyModule_AddStringConstant(pypcap, "__version__", PYPCAP_VERSION);
}

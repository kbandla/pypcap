/*
    A pure Python/C binding for libpcap
    Copyright (C) Kiran Bandla <kbandla@in2void.com>
 */

#include <Python.h>
#include <structmember.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "docs.h"

#define PYPCAP_VERSION  "0.1"
#define PyCHECK_SELF if(!self->pcap){   \
            PyErr_SetString(PyPcap_Error, "Please create a pcap capture instance first"); \
            return NULL;}   \

static PyObject *PyPcap_Error;

typedef struct {
    PyObject_HEAD
    pcap_t *pcap;           // pcap object
    PyObject *interface;    // interface to capture on
    PyObject *error;        // error message
    PyObject *callback;     // callback function
} PyPcapObject;

PyObject *arglist;
PyObject *result;
//PyObject *callback;
int pcap_offset;
char pcap_errbuf[PCAP_ERRBUF_SIZE];


static void
pypcap_dealloc(PyPcapObject* self)
{
    Py_XDECREF(self->interface);
    Py_XDECREF(self->error);
    if(self->pcap)
        pcap_close(self->pcap);
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
pypcap_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyPcapObject *self;
    self = (PyPcapObject*)type->tp_alloc(type, 0);
    self->pcap = NULL;
    self->interface = Py_None;
    self->callback = Py_None;
    self->error = Py_None;
    return (PyObject *)self;
}

static int
pypcap_init(PyPcapObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *interface=NULL, *tmp;
    static char *kwlist[] = {"interface", NULL};
    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwlist, &interface))
        return -1; 

    if (interface) {
        tmp = self->interface;
        Py_INCREF(interface);
        self->interface = interface;
        Py_XDECREF(tmp);
    }

    return 0;
}

static PyObject*
pypcap_pcap_lib_version(PyObject *self)
{
    PyObject *version;
    version = PyString_FromString(pcap_lib_version());
    return version;
}

static PyObject *
pypcap_pcap_create(PyPcapObject *self, PyObject *args)
{
    char *interface=NULL;
    if (!PyArg_ParseTuple(args, "s", &interface)){
        return NULL;
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
    // save interface
    self->interface = PyString_FromString( interface );
    Py_RETURN_TRUE;
}


static PyObject *
pypcap_lookupdev(PyObject *self)
{
    PyObject *pcap_device;
    char *device=NULL;
    device = pcap_lookupdev(pcap_errbuf);
    pcap_device = PyString_FromString( device );
    return pcap_device;
}

static PyObject *
pypcap_pcap_findalldevs(PyObject *self)
{
    PyObject *interfacesL = PyList_New(0);  // list of interfaces
    PyObject *tmp;
    
    pcap_if_t *interfaces = NULL;
    if( pcap_findalldevs(&interfaces, pcap_errbuf) != 0){
        // Error reading interface details
        PyErr_SetString(PyPcap_Error, pcap_errbuf);
        return NULL; 
        //return interfacesL;
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

/*
TODO: make sure that the interfce really exits
*/
static PyObject *
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
        PyErr_SetString(PyPcap_Error, "PyDict_SetItem error");
        return NULL;
    }
    if(PyTuple_SetItem(network, 1, PyString_FromString(mask_text))){
        PyErr_SetString(PyPcap_Error, "PyDict_SetItem error");
        return NULL;
    }

    return network;
    
}

static PyObject *
pypcap_pcap_datalink(PyPcapObject *self)
{
    PyObject *linklayer;
    PyCHECK_SELF;
    linklayer = PyInt_FromLong((long)pcap_datalink(self->pcap));
    return linklayer;
}

static PyObject *
pypcap_pcap_datalink_val_to_name(PyPcapObject *self)
{
    PyObject *link_name;
    PyCHECK_SELF;
    link_name = PyString_FromString(pcap_datalink_val_to_name( pcap_datalink(self->pcap)) );
    return link_name;
}

static PyObject *
pypcap_pcap_datalink_val_to_description(PyPcapObject *self)
{
    PyObject *link_description;
    PyCHECK_SELF;
    link_description = PyString_FromString( pcap_datalink_val_to_description( pcap_datalink(self->pcap)) );
    return link_description;
}

static PyObject *
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
    Py_RETURN_TRUE;
}

static PyObject *
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
    Py_RETURN_TRUE;

}

static PyObject *
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
    Py_RETURN_TRUE;

}

static PyObject *
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
    Py_RETURN_TRUE;
}

static PyObject *
pypcap_pcap_activate(PyPcapObject *self)
{
    PyCHECK_SELF;
    if(pcap_activate(self->pcap) !=0 ){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    Py_RETURN_TRUE;
}

static PyObject *
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
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }

    if (pcap_compile(self->pcap,&filter, (char *)capture_filter, 1, mask) !=0){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }

    if(pcap_setfilter(self->pcap,&filter) !=0){
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }

    Py_RETURN_TRUE;
}


void handle_pkt(PyPcapObject *self, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    if(PyErr_CheckSignals()){
        //printf("Got termination signal\n");
        pcap_breakloop(self->pcap);
    }
    // TODO: extract the timestamp and pass on the call back
    arglist = Py_BuildValue("(s#)", packet, pkthdr->len);
    result = PyObject_CallObject( self->callback, arglist);
    Py_DECREF(arglist);
}

static PyObject *
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
    Py_RETURN_TRUE;
}

static PyObject *
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
    ret = pcap_loop(self->pcap, capture_count, handle_pkt, self);
    if(ret == -1) {
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL;
    }
    Py_RETURN_TRUE;
}

static PyObject *
pypcap_pcap_sendpacket(PyPcapObject *self, PyObject *args)
{
    u_char *buffer;
    int length;
    PyCHECK_SELF;
    if (!PyArg_ParseTuple(args, "s#", &buffer, &length)){
        PyErr_SetString(PyPcap_Error, "Error assigning to inputString object");
        return NULL;
    }
    
    printf("length = %d\n", length);

    if(pcap_sendpacket(self->pcap, buffer, length) == -1){
        //error
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL;
    }
    printf("OK?\n");
    Py_RETURN_TRUE;

}

static PyObject *
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

static PyObject *
pypcap_pcap_set_rfmon(PyPcapObject *self, PyObject *args)
{
    PyObject *input;
    PyCHECK_SELF;
    int rfmon;
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

static PyMemberDef PyPcap_Members[] = {
    {"interface", T_OBJECT_EX, offsetof(PyPcapObject, interface), 0, "Interface name"},
    {"error", T_OBJECT_EX, offsetof(PyPcapObject, error), 0, "Error message"},
    {"callback", T_OBJECT_EX, offsetof(PyPcapObject, callback), 0, "Callback function"},
    {NULL}  /* Sentinel */
};

static PyMethodDef PyPcap_Methods[] = {
    {"pcap_create", pypcap_pcap_create, METH_VARARGS, pcap_create__doc__},
    {"pcap_datalink", pypcap_pcap_datalink, METH_VARARGS, pcap_datalink__doc__},
    {"pcap_datalink_val_to_name", pypcap_pcap_datalink_val_to_name, METH_VARARGS, pcap_datalink_val_to_name__doc__},
    {"pcap_datalink_val_to_description", pypcap_pcap_datalink_val_to_description, METH_VARARGS, pcap_datalink_val_to_description__doc__},
    {"pcap_set_buffer_size", pypcap_pcap_set_buffer_size, METH_VARARGS, pcap_set_buffer_size__doc__},
    {"pcap_set_snaplen", pypcap_pcap_set_snaplen, METH_VARARGS, pcap_set_snaplen__doc__},
    {"pcap_set_timeout", pypcap_pcap_set_timeout, METH_VARARGS, pcap_set_timeout__doc__},
    {"pcap_set_promisc", pypcap_pcap_set_promisc, METH_VARARGS, pcap_set_promisc__doc__},
    {"pcap_activate",       pypcap_pcap_activate,   METH_VARARGS, pcap_activate__doc__},
    {"pcap_compile",        pypcap_pcap_compile,    METH_VARARGS, pcap_compile__doc__},
    {"pcap_set_callback",   pypcap_pcap_set_callback, METH_VARARGS, pcap_set_callback__doc__},
    {"pcap_loop",           pypcap_pcap_loop,       METH_VARARGS|METH_KEYWORDS, pcap_loop__doc__},
    {"pcap_sendpacket",     pypcap_pcap_sendpacket, METH_VARARGS, pcap_sendpacket__doc__},
    {"pcap_set_rfmon",      pypcap_pcap_set_rfmon,  METH_VARARGS, pcap_set_rfmon__doc__},
    {"pcap_can_set_rfmon",  pypcap_pcap_can_set_rfmon, METH_VARARGS, pcap_can_set_rfmon__doc__},
    {"pcap_list_datalinks", pypcap_pcap_list_datalinks, METH_VARARGS, pcap_list_datalinks__doc__},
    {NULL, NULL}  /* Sentinel */
};

static PyMethodDef module_methods[] = {
    // Some helper funtions
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
    if (PyType_Ready(&PyPcapType) < 0)
        return;
    // 'pcap' module
    pypcap = Py_InitModule3("pypcap", module_methods, "C/Python bindings for libpcap");
    if( pypcap == NULL)
        return;
    PyPcap_Error = PyErr_NewException("pcap.Error", NULL, NULL);
    Py_INCREF(&PyPcapType);
    PyModule_AddObject(pypcap, "pcap", (PyObject *)&PyPcapType);
}

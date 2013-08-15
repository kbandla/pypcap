/*
    A pure Python/C binding for libpcap
    Copyright (C) Kiran Bandla <kbandla@in2void.com>
 */

#include <Python.h>
#include <structmember.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>

#define PYPCAP_VERSION  "0.1"

static PyObject *PyPcap_Error;

typedef struct {
    PyObject_HEAD
    pcap_t *pcap;           // pcap object
    PyObject *interface;    // interface to capture on
    PyObject *error;        // error message
} PyPcapObject;

PyObject *arglist;
PyObject *result;
PyObject *callback;
int pcap_offset;
char pcap_errbuf[PCAP_ERRBUF_SIZE];

static void
pypcap_dealloc(PyPcapObject* self){
    Py_XDECREF(self->interface);
    Py_XDECREF(self->error);
    if(self->pcap)
        pcap_close(self->pcap);
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
pypcap_new(PyTypeObject *type, PyObject *args, PyObject *kwds){
    PyPcapObject *self;
    self = (PyPcapObject*)type->tp_alloc(type, 0);
    if (self != NULL) {
    }
    self->pcap = NULL;
    self->interface = NULL;
    return (PyObject *)self;
}

static int
pypcap_init(PyPcapObject *self, PyObject *args, PyObject *kwds){
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
pypcap_pcap_lib_version(PyPcapObject *self){
    PyObject *version;
    version = PyString_FromString(pcap_lib_version());
    return version;
}

static PyObject *
pypcap_pcap_create(PyPcapObject *self, PyObject *args){
    char *interface=NULL;
    if (!PyArg_ParseTuple(args, "s", &interface)){
        return NULL;
    }
    if(getuid()!= 0){
       PyErr_SetString(PyPcap_Error, "Sniffing requires root privileges");
        return NULL; 
    }
    self->pcap = pcap_create( interface, pcap_errbuf );
    if(!self->pcap){
       PyErr_SetString(PyPcap_Error, pcap_errbuf);
        return NULL; 
    }
    // save interface
    self->interface = PyString_FromString( interface );
    Py_RETURN_TRUE;
}


static PyObject *
pypcap_lookupdev(PyPcapObject *self){
    PyObject *pcap_device;
    char *device=NULL;
    device = pcap_lookupdev(pcap_errbuf);
    pcap_device = PyString_FromString( device );
    return pcap_device;
}

static PyObject *
pypcap_pcap_findalldevs(PyPcapObject *self){
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
            //error
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
pypcap_pcap_lookupnet(PyPcapObject *self, PyObject *args){
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
        //error
        PyErr_SetString(PyPcap_Error, "inet_ntop error");
        return NULL;
    }
    if(!inet_ntop(AF_INET, &maskaddr, mask_text, INET_ADDRSTRLEN)){
        //error
        PyErr_SetString(PyPcap_Error, "inet_ntop error");
        return NULL;
    }
    
    if(PyTuple_SetItem(network, 0, PyString_FromString(ipaddr_text))){
        //error
        PyErr_SetString(PyPcap_Error, "PyDict_SetItem error");
        return NULL;
    }
    if(PyTuple_SetItem(network, 1, PyString_FromString(mask_text))){
        //error
        PyErr_SetString(PyPcap_Error, "PyDict_SetItem error");
        return NULL;
    }

    return network;
    
}

static PyObject *
pypcap_pcap_datalink(PyPcapObject *self){
    PyObject *linklayer;
    linklayer = PyInt_FromLong((long)pcap_datalink(self->pcap));
    return linklayer;
}

static PyObject *
pypcap_pcap_datalink_val_to_name(PyPcapObject *self){
    PyObject *link_name;
    link_name = PyString_FromString(pcap_datalink_val_to_name( pcap_datalink(self->pcap)) );
    return link_name;
}

static PyObject *
pypcap_pcap_datalink_val_to_description(PyPcapObject *self){
    PyObject *link_description;
    link_description = PyString_FromString( pcap_datalink_val_to_description( pcap_datalink(self->pcap)) );
    return link_description;
}

static PyObject *
pypcap_pcap_set_buffer_size(PyPcapObject *self, PyObject *args){
    int PCAP_CAPTURE_BUFFER;
    if (!PyArg_ParseTuple(args, "i", &PCAP_CAPTURE_BUFFER)){
        return NULL;
    }
    if(pcap_set_buffer_size(self->pcap, PCAP_CAPTURE_BUFFER) !=0 ){
        //error
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    Py_RETURN_TRUE;
}

static PyObject *
pypcap_pcap_set_snaplen(PyPcapObject *self, PyObject *args){
    int PCAP_SNAPLEN;
    if (!PyArg_ParseTuple(args, "i", &PCAP_SNAPLEN)){
        return NULL;
    }
    if(pcap_set_snaplen(self->pcap, PCAP_SNAPLEN) !=0 ){
        //error
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    Py_RETURN_TRUE;

}

static PyObject *
pypcap_pcap_set_timeout(PyPcapObject *self, PyObject *args){
    int PCAP_READ_TIMEOUT;
    if (!PyArg_ParseTuple(args, "i", &PCAP_READ_TIMEOUT)){
        return NULL;
    }
    if(pcap_set_timeout(self->pcap, PCAP_READ_TIMEOUT) !=0 ){
        //error
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    Py_RETURN_TRUE;

}

static PyObject *
pypcap_pcap_set_promisc(PyPcapObject *self, PyObject *args){
    int PROMISCUOUS;
    if (!PyArg_ParseTuple(args, "i", &PROMISCUOUS)){
        return NULL;
    }
    if(pcap_set_promisc(self->pcap, PROMISCUOUS) !=0 ){
        //error
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    Py_RETURN_TRUE;
}

static PyObject *
pypcap_pcap_activate(PyPcapObject *self){
    if(pcap_activate(self->pcap) !=0 ){
        //error    
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL; 
    }
    Py_RETURN_TRUE;
}

static PyObject *
pypcap_pcap_compile(PyPcapObject *self, PyObject *args){
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


void handle_pkt(u_char *pcap, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    if(PyErr_CheckSignals()){
        //printf("Got termination signal\n");
        pcap_breakloop(pcap);
    }
    // extract the timestamp and pass on the call back
    arglist = Py_BuildValue("(s#)", packet, pkthdr->len);
    result = PyObject_CallObject( callback, arglist);
    Py_DECREF(arglist);
}

static PyObject *
pypcap_pcap_set_callback(PyPcapObject *self, PyObject *args){
    PyObject *result = NULL;
    PyObject *temp;
    if (PyArg_ParseTuple(args, "O:set_callback", &temp)) {
        if (!PyCallable_Check(temp)) {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
            return NULL;
        }
        Py_XINCREF(temp);
        callback = temp;
        Py_INCREF(Py_None);
        result = Py_None;
    }
    return result;
}

static PyObject *
pypcap_pcap_loop(PyPcapObject *self, PyObject *args){
    int capture_count = -1;
    int ret;
    if (!PyArg_ParseTuple(args, "|i", &capture_count)){
        PyErr_SetString(PyPcap_Error, "Error setting capture_count");
        return NULL;
    }
    ret = pcap_loop(self->pcap, capture_count, handle_pkt, self->pcap);
    if(ret == 0){
        //everything went well, all packets were consumed
    } else if(ret == -1) {
        //error
        PyErr_SetString(PyPcap_Error, pcap_geterr(self->pcap));
        return NULL;
    }
    Py_RETURN_TRUE;
}

static PyMemberDef PyPcap_Members[] = {
    {"interface", T_OBJECT_EX, offsetof(PyPcapObject, interface), 0, "Interface name"},
    {"error", T_OBJECT_EX, offsetof(PyPcapObject, error), 0, "Error message"},
    {NULL}  /* Sentinel */
};

static PyMethodDef PyPcap_Methods[] = {
    {"pcap_create", pypcap_pcap_create, METH_VARARGS, "Create a new capture object"},
    {"pcap_datalink", pypcap_pcap_datalink, METH_VARARGS, "get the link-layer header type"},
    {"pcap_datalink_val_to_name", pypcap_pcap_datalink_val_to_name, METH_VARARGS, "get a name or description for a link-layer header type value"},
    {"pcap_datalink_val_to_description", pypcap_pcap_datalink_val_to_description, METH_VARARGS, "get a name or description for a link-layer header type value"},
    {"pcap_set_buffer_size", pypcap_pcap_set_buffer_size, METH_VARARGS, "set the buffer size for a not-yet-activated capture handle"},
    {"pcap_set_snaplen", pypcap_pcap_set_snaplen, METH_VARARGS, "set the snapshot length for a not-yet-activated capture handle"},
    {"pcap_set_timeout", pypcap_pcap_set_timeout, METH_VARARGS, "set the read timeout for a not-yet-activated capture handle"},
    {"pcap_set_promisc", pypcap_pcap_set_promisc, METH_VARARGS, "set promiscuous mode for a not-yet-activated capture handle"},
    {"pcap_activate", pypcap_pcap_activate, METH_VARARGS, "activate a capture handle"},
    {"pcap_compile", pypcap_pcap_compile, METH_VARARGS, "compile a filter expression"},
    {"pcap_set_callback", pypcap_pcap_set_callback, METH_VARARGS, "set a callback"},
    {"pcap_loop", pypcap_pcap_loop, METH_VARARGS, "Start capture loop"},
    {NULL, NULL}  /* Sentinel */
};

static PyMethodDef module_methods[] = {
    // Some helper funtions
    {"pcap_lookupdev", pypcap_lookupdev, METH_VARARGS, "Find the first available interface"},
    {"pcap_findalldevs", pypcap_pcap_findalldevs, METH_VARARGS, "Find all available interface"},
    {"pcap_lookupnet", pypcap_pcap_lookupnet, METH_VARARGS, "Get interface details"},
    {"pcap_lib_version", pypcap_pcap_lib_version, METH_VARARGS, "information about the version of the libpcap library being used"},
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

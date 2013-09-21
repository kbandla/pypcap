/*
    A pure Python/C binding for libpcap
    pypcap.h : prototypes and definitions
    Copyright (C) Kiran Bandla <kbandla@in2void.com>
 */

#include <Python.h>
#include <pcap.h>

#define PYPCAP_VERSION  "0.3"
#define PyCHECK_SELF if(!self->pcap){   \
            PyErr_SetString(PyPcap_Error, "Please create a pcap capture instance first"); \
            return NULL;}   \

typedef struct {
    PyObject_HEAD
    pcap_t *pcap;               // pcap object
    pcap_dumper_t *pcap_dumper; //pcap dumper object
    PyObject *config;           // various settings
    PyObject *interface;        // interface to capture on
    PyObject *callback;         // callback function
} PyPcapObject;

static void pypcap_dealloc(PyPcapObject* self);
static PyObject* pypcap_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int pypcap_init(PyPcapObject *self, PyObject *args, PyObject *kwds);
static PyObject* pypcap_pcap_lib_version(PyObject *self, PyObject *args);
static PyObject* pypcap_pcap_create(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_open_offline(PyPcapObject *self, PyObject *args);

void pcap_dumper_callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
static PyObject* pypcap_pcap_dump_open(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_dump(PyPcapObject *self, PyObject *args, PyObject *kwds);
static PyObject* pypcap_lookupdev(PyObject *self, PyObject *args);
static PyObject* pypcap_pcap_findalldevs(PyObject *self, PyObject *args);
static PyObject* pypcap_pcap_lookupnet(PyObject *self, PyObject *args);
static PyObject* pypcap_pcap_datalink(PyPcapObject *self);
static PyObject* pypcap_pcap_datalink_name_to_val(PyObject *self, PyObject *args);
static PyObject* pypcap_pcap_datalink_val_to_name(PyPcapObject *self);
static PyObject* pypcap_pcap_datalink_val_to_description(PyPcapObject *self);
static PyObject* pypcap_pcap_set_buffer_size(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_set_snaplen(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_set_timeout(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_set_promisc(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_activate(PyPcapObject *self);
static PyObject* pypcap_pcap_compile(PyPcapObject *self, PyObject *args);
void handle_pkt(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
static PyObject* pypcap_pcap_set_callback(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_loop(PyPcapObject *self, PyObject *args, PyObject *kwds);
static PyObject* pypcap_pcap_sendpacket(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_can_set_rfmon(PyPcapObject *self);
static PyObject* pypcap_pcap_set_rfmon(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_list_datalinks(PyPcapObject *self);
static PyObject* pypcap_pcap_snapshot(PyPcapObject *self, PyObject *args);
static PyObject* pypcap_pcap_stats(PyPcapObject *self);
#ifdef WIN32
static PyObject* pypcap_pcap_stats(PyPcapObject *self);
#endif


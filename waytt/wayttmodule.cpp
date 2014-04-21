/*
*  This file is part of WAYTT.
*
*   WAYTT is free software: you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation, either version 3 of the License, or
*   (at your option) any later version.
*
*   WAYTT is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with WAYTT.  If not, see <http://www.gnu.org/licenses/>.
*/

/// Python requires that its header preceed system headers
#ifdef _WIN32
#define WINDOWS
#define HAVE_ROUND // Tell python that windows already has a round function
#endif

#include <Python.h>

#include <iostream>
#include <winsock2.h>


/// pcap defines
 
#define MAX_PACKET_SIZE 65535
#define GROUP_PACKETS_TO_MS 10
#define NUM_PACKETS -1
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)

#include <pcap.h>

extern "C" {


/* Ethernet header */
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src, ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

static PyObject * adaptors(PyObject *self) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0, total = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	PyObject* adaptorList = PyList_New(0);

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	for (d = alldevs; d != NULL; d = d->next) total++;

	if (total == 0) {
		pcap_freealldevs(alldevs);
		return adaptorList;
	}

	for (d = alldevs; d != NULL; d = d->next) {
		assert(d->name);
		assert(d->description);
		PyObject* arglist = Py_BuildValue("(ss)", d->name, d->description);
		PyList_Append(adaptorList, arglist);
		Py_DECREF(arglist);
	}

	pcap_freealldevs(alldevs);

	return adaptorList;
}

static PyObject *callback = NULL;
void got_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);

static PyObject* start(PyObject *self, PyObject *args) {
	PyObject* devices;
	PyObject* local;
	PyObject* mask;
	if (!PyArg_UnpackTuple(args, "start", 4, 4, &devices, &local, &mask, &callback))
		return NULL;

	if (!PyList_Check(devices)) {
		PyErr_SetString(PyExc_TypeError, "devices must be list");
		return NULL;
	}

	if (!PyLong_Check(local)) {
		PyErr_SetString(PyExc_TypeError, "local must be ipv4 address as a long");
		return NULL;
	}
		
	if (!PyLong_Check(mask)) {
		PyErr_SetString(PyExc_TypeError, "mask must be ipv4 mask as a long");
		return NULL;
	}

	if (!PyCallable_Check(callback)) {
		PyErr_SetString(PyExc_TypeError, "callback parameter must be callable");
		return NULL;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;			/* compiled filter program (expression) */
	int i, j;
	int numDevices = PyList_Size(devices);
	int count = numDevices;
	u_long filter[2] = { PyLong_AsUnsignedLong(local), PyLong_AsUnsignedLong(local) };
    
	/* prepare the error buffer */
	errbuf[0] = '\0';
	
	/* open capture device */
	pcap_t** handles = (pcap_t**) malloc(sizeof(pcap_t*)*count);
	j=0;
	for (i = 0; i<numDevices; i++) {
		if (!PyUnicode_Check(PyList_GetItem(devices, i))) {
			count--;
			continue;
		}
		PyObject* device = PyList_GetItem(devices, i);
		
		handles[j] = pcap_open_live(PyUnicode_AsUTF8(device), MAX_PACKET_SIZE, false, GROUP_PACKETS_TO_MS, errbuf);
		if (handles[j] == NULL || errbuf[0] != '\0') {
			fprintf(stderr, "Couldn't open device %s: %s\n", PyUnicode_AsUTF8(device), errbuf);
			getchar();
			count--;
			continue;
		}

		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handles[j]) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", PyUnicode_AsUTF8(device));
			count--;
			continue;
		}

		/* compile the filter expression */
		if (pcap_compile(handles[j], &fp, "ip", true, 0) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", "ip", pcap_geterr(handles[j]));
			count--;
			continue;
		}

		/* apply the compiled filter */
		if (pcap_setfilter(handles[j], &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", "ip", pcap_geterr(handles[j]));
			count--;
			continue;
		}
		j++;
	}
	
	int res, packets;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	do {
		for (j=0;j<count;j++){
			for (packets=0;packets<1000;packets++) {
				res = pcap_next_ex(handles[j], &header, &pkt_data);
				if (res != 1) break;
				got_packet((u_char*)filter, header, pkt_data);
			}
			if (res<0) break;
		}
	} while (res>=0);
	
	pcap_freecode(&fp);
	for (j = 0; j < count; j++) {
		pcap_close(handles[j]);
		free(handles[j]);
	}
	callback = NULL;
	Py_RETURN_NONE;
}

void got_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet) {
	int d = 0, u = 0;
	u_long mask;
	u_long local;
	int src_remote, dst_remote;

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */

	int size_ip;

	mask = ((u_long*) args)[0];
	local = ((u_long*) args)[1];

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);


	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
    
	unsigned long src = _byteswap_ulong(ip->ip_src.s_addr);
	unsigned long dst = _byteswap_ulong(ip->ip_dst.s_addr);

	src_remote = (src ^ local) & mask;
	dst_remote = (dst ^ local) & mask;
    
	if (!src_remote) {
        if (!dst_remote) {
            //printf("Internal\n");
			return;
        } else {
            //printf("Outgoing\n");
            u = header->len;
        }
	} else {
        if (!dst_remote) {
            //printf("Incoming\n");
            d = header->len;
        } else {
            //printf("External\n");
			return;
        }
	}
	
	if (callback != NULL) {
		PyObject* srcPy = PyLong_FromUnsignedLong(src);
		PyObject* dstPy = PyLong_FromUnsignedLong(dst);
		PyObject* arglist = Py_BuildValue("(iiOO)", d, u, srcPy, dstPy);
		PyObject* result = PyObject_CallObject(callback, arglist);
		Py_DECREF(srcPy);
		Py_DECREF(dstPy);
		Py_DECREF(result);
		Py_DECREF(arglist);
	}
	
	return;
}

static PyMethodDef module_methods[] = {
	{ "adaptors", (PyCFunction) adaptors, METH_NOARGS, NULL },
	{ "start", (PyCFunction) start, METH_VARARGS, NULL },
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"waytt",     /* m_name */
	"Who Are You Talking To?, a python c module for measuring network traffic by destination and source.",  /* m_doc */
	-1,                  /* m_size */
	module_methods,      /* m_methods */
	NULL,                /* m_reload */
	NULL,      /* m_traverse */
	NULL,         /* m_clear */
	NULL,                /* m_free */
};

PyMODINIT_FUNC PyInit_waytt(void)
{
	return PyModule_Create(&moduledef);
}

}

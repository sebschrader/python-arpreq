#include <Python.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#if PY_MAJOR_VERSION >= 3
#  define IS_PY3
#endif

struct arpreq_state {
    int socket;
};

#ifdef IS_PY3
#define GETSTATE(m) ((struct arpreq_state*)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
static struct arpreq_state _state;
#endif

static PyObject *
mac_to_string(unsigned char *eap) {
    char buf[18];
    sprintf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            eap[0], eap[1], eap[2], eap[3], eap[4], eap[5]);
#ifdef IS_PY3
    return PyUnicode_FromString(buf);
#else
    return PyString_FromString(buf);
#endif
}

static PyObject *
arpreq(PyObject * self, PyObject * args) {
    const char * addr_str;
    if (!PyArg_ParseTuple(args, "s", &addr_str)) {
        return NULL;
    }
    struct arpreq_state *st = GETSTATE(self);

    struct arpreq arpreq;
    memset(&arpreq, 0, sizeof(arpreq));

    struct sockaddr_in *sin = (struct sockaddr_in *) &arpreq.arp_pa;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, addr_str, &(sin->sin_addr)) != 1) {
        PyErr_Format(PyExc_ValueError, "Invalid IPv4 address %s", addr_str);
        return NULL;
    }
    int addr = sin->sin_addr.s_addr;

    struct ifaddrs * head_ifa;
    if (getifaddrs(&head_ifa) == -1) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    for (struct ifaddrs * ifa = head_ifa; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (ifa->ifa_flags & IFF_POINTOPOINT)
            continue;
        int ifaddr = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr.s_addr;
        int netmask = ((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr.s_addr;
        if ((ifaddr & netmask) == (addr & netmask)) {
            if (ifaddr == addr) {
                struct ifreq ifreq;
                strncpy(ifreq.ifr_name, ifa->ifa_name, IFNAMSIZ);
                freeifaddrs(head_ifa);
                if (ioctl(st->socket, SIOCGIFHWADDR, &ifreq) == -1) {
                    return PyErr_SetFromErrno(PyExc_OSError);
                }
                return mac_to_string((unsigned char *)ifreq.ifr_hwaddr.sa_data);
            }
            strncpy(arpreq.arp_dev, ifa->ifa_name, sizeof(arpreq.arp_dev));
            break;
        }
    }
    freeifaddrs(head_ifa);
    if (arpreq.arp_dev[0] == 0) {
        Py_RETURN_NONE;
    }

    if (ioctl(st->socket, SIOCGARP, &arpreq) == -1) {
        if (errno == ENXIO) {
            Py_RETURN_NONE;
        } else {
            return PyErr_SetFromErrno(PyExc_OSError);
        }
    }

    if (arpreq.arp_flags & ATF_COM) {
        return mac_to_string((unsigned char *)arpreq.arp_ha.sa_data);
    } else {
        Py_RETURN_NONE;
    }
}

static PyMethodDef arpreq_methods[] = {
    {"arpreq", arpreq, METH_VARARGS, "Probe the kernel ARP cache for the MAC address of an IPv4 address."},
    {NULL, NULL, 0, NULL}
};

#ifdef IS_PY3

static void arpreq_free(void *m) {
    close(GETSTATE(m)->socket);
}

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "arpreq",
        "Translate IP addresses to MAC addresses using the kernel's arp(7) interface.",
        sizeof(struct arpreq_state),
        arpreq_methods,
        NULL,
        NULL,
        NULL,
        arpreq_free
};

#define INITERROR return NULL

PyMODINIT_FUNC
PyInit_arpreq(void)
#else
#define INITERROR return

PyMODINIT_FUNC
initarpreq(void)
#endif
{
    PyObject * module;
#ifdef IS_PY3
    module = PyModule_Create(&moduledef);
#else
    module = Py_InitModule("arpreq", arpreq_methods);
#endif
    if (module == NULL) {
        INITERROR;
    }
    struct arpreq_state *st = GETSTATE(module);

    st->socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (st->socket == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        Py_DECREF(module);
        INITERROR;
    }
#ifdef IS_PY3
    return module;
#endif
}

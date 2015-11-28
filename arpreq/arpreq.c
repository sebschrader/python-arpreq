#include <Python.h>
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

struct arpreq_state {
    int socket;
};

#if PY_MAJOR_VERSION >= 3
#define PyStringType_FromFormat PyUnicode_FromFormat
#define GETSTATE(m) ((struct arpreq_state*)PyModule_GetState(m))
#else
#define PyStringType_FromFormat PyString_FromFormat
#define GETSTATE(m) (&_state)
static struct arpreq_state _state;
#endif

static void set_verror(PyObject * exc, const char *format, va_list args) {
    char * msg;
    if (vasprintf(&msg, format, args) == -1) {
        PyErr_NoMemory();
        return;
    }
    PyErr_SetString(exc, msg);
    free(msg);
}

static void set_error(PyObject * exc, const char* format, ...) {
    va_list args;
    va_start(args, format);
    set_verror(exc, format, args);
    va_end(args);
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
        set_error(PyExc_ValueError, "Invalid IPv4 address %s", addr_str);
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
            strncpy(arpreq.arp_dev, ifa->ifa_name, sizeof(arpreq.arp_dev));
            break;
        }
    }
    freeifaddrs(head_ifa);
    if (arpreq.arp_dev[0] == 0) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    if (ioctl(st->socket, SIOCGARP, &arpreq) == -1) {
        if (errno == ENXIO) {
            Py_INCREF(Py_None);
            return Py_None;
        } else {
            return PyErr_SetFromErrno(PyExc_OSError);
        }
    }

    if (arpreq.arp_flags & ATF_COM) {
        unsigned char *eap = (unsigned char *) arpreq.arp_ha.sa_data;
        return PyStringType_FromFormat("%02x:%02x:%02x:%02x:%02x:%02x",
                                       eap[0], eap[1], eap[2],
                                       eap[3], eap[4], eap[5]);
    } else {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

static PyMethodDef arpreq_methods[] = {
    {"arpreq", arpreq, METH_VARARGS, "Probe the kernel ARP cache for the MAC address of an IPv4 address."},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3

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
#if PY_MAJOR_VERSION >= 3
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
#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}

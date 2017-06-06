#include <Python.h>
#include <stddef.h>
#include <stdbool.h>
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

#if (PY_VERSION_HEX >= 0x3050000) && !defined(PYPY_VERSION_NUM)
#  define HAVE_PEP489
#endif

struct arpreq_state {
    PyObject *ipaddress_types;
    int socket;
};

#if defined(IS_PY3) && !defined(PYPY_VERSION_NUM)
#define GETSTATE(m) ((struct arpreq_state*)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
static struct arpreq_state _state;
#endif

/**
 * Convert a binary MAC address into a lowercase Python str object.
 */
static inline PyObject *
mac_to_string(const unsigned char *eap)
{
    char buffer[18];
    sprintf(buffer, "%02hhx:%02hhx:%02hhx:%02hhx:%02x:%02hhx",
            eap[0], eap[1], eap[2], eap[3], eap[4], eap[5]);
#ifdef IS_PY3
    return PyUnicode_DecodeASCII(buffer, sizeof(buffer) - 1, NULL);
#else
    return PyString_FromStringAndSize(buffer, sizeof(buffer) - 1);
#endif
}

/**
 * Try to convert a Python int object into an struct in_addr.
 *
 * The Python object must ba an int object (unchecked).
 * Returns -1 on failure and 0 on success.
 */
static inline int
address_from_long(PyObject *object, struct in_addr *address)
{
    unsigned long l = PyLong_AsUnsignedLong(object);
    if (PyErr_Occurred()) {
        if (PyErr_ExceptionMatches(PyExc_OverflowError)) {
            goto overflow;
        }
        return -1;
    }
    if (l > UINT32_MAX) {
        goto overflow;
    }
    address->s_addr = htonl(l);
    return 0;
overflow:
    PyErr_SetString(PyExc_ValueError,
            "IPv4 addresses given as integers "
            "must be between zero and UINT32_MAX");
    return -1;
}

static inline int
address_from_bytes(PyObject *bytes, struct in_addr *address)
{
    const char *ascii_string = PyBytes_AS_STRING(bytes);
    if (inet_pton(AF_INET, ascii_string, address) != 1) {
        PyErr_Format(PyExc_ValueError, "Invalid IPv4 address: %s", ascii_string);
        return -1;
    }
    return 0;
}


/**
 * Try to convert a Python unicode object into an struct in_addr.
 *
 * The Python object must be a unicode object (unchecked).
 * Returns -1 on failure and 0 on success.
 */
static inline int
address_from_unicode(PyObject *unicode, struct in_addr *address)
{
    PyObject *bytes = PyUnicode_AsASCIIString(unicode);
    if (bytes == NULL)
        return -1;
    int rv = address_from_bytes(bytes, address);
    Py_DECREF(bytes);
    return rv;
}


/**
 * Try to coerce the arpreq argument into an IPv4 address
 */
static inline int
coerce_argument(PyObject *self, PyObject *object, struct in_addr *address)
{
    if (PyLong_Check(object)) {
        return address_from_long(object, address);
    }
#ifndef IS_PY3
    if (PyInt_Check(object)) {
        PyObject *python_long = PyNumber_Long(object);
        if (!python_long) {
            return -1;
        }
        int result = address_from_long(python_long, address);
        Py_DECREF(python_long);
        return result;
    }
#endif
    if (PyUnicode_Check(object)) {
        return address_from_unicode(object, address);
    }
    if (PyBytes_Check(object)) {
        return address_from_bytes(object, address);
    }
    if (PyObject_IsInstance(object, GETSTATE(self)->ipaddress_types)) {
        PyObject *python_string = PyObject_Str(object);
        if (!python_string) {
            return -1;
        }
#ifdef IS_PY3
        int result = address_from_unicode(python_string, address);
#else
        int result = address_from_bytes(python_string, address);
#endif
        Py_DECREF(python_string);
        return result;
    }
    PyErr_Format(PyExc_TypeError, "argument must be str, int, "
            "ipaddr.IPv4, ipaddress.IPv4Address or "
            "netaddr.IPAddress, not %s",
            object == Py_None ? "None" : object->ob_type->tp_name);
    return -1;
}

PyDoc_STRVAR(arpreq_arpreq_doc,
"arpreq(ipv4_address) -> mac\n"
"\n"
"Probe the kernel ARP cache for the MAC address of an IPv4 address.\n"
"The IPv4 address may be a str, int, ipaddr.IPv4Address,\n"
"ipaddress.IPv4Address or netaddr.IPAddress object.\n"
"\n"
"Note: No actual ARP request is performed, only the kernel cache is queried."
);

/**
 * Probe the Kernel ARP cache by issuing a SIOCGARP ioctl call.
 *
 * See arp(7) for details.
 */
static PyObject *
arpreq(PyObject *self, PyObject *arg)
{
    struct arpreq_state *st = GETSTATE(self);

    struct sockaddr_in ip_address;
    memset(&ip_address, 0, sizeof(ip_address));
    ip_address.sin_family = AF_INET;
    if (coerce_argument(self, arg, &(ip_address.sin_addr)) == -1) {
        return NULL;
    }

    uint32_t addr = ip_address.sin_addr.s_addr;
    bool error = false;
    bool found = false;
    struct sockaddr mac_address;
    memset(&mac_address, 0, sizeof(mac_address));
    struct ifaddrs *head_ifa = NULL;

    Py_BEGIN_ALLOW_THREADS

    if (getifaddrs(&head_ifa) == -1) {
        error = true;
        goto cleanup;
    }

    for (struct ifaddrs *ifa = head_ifa; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (ifa->ifa_flags & IFF_POINTOPOINT)
            continue;
        uint32_t ifaddr = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr.s_addr;
        uint32_t netmask = ((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr.s_addr;
        uint32_t dstaddr = ((struct sockaddr_in *) ifa->ifa_dstaddr)->sin_addr.s_addr;
        if (((netmask == 0xFFFFFFFF) && (addr == dstaddr))
                || (ifaddr & netmask) == (addr & netmask)) {
            if (ifaddr == addr) {
                struct ifreq ifreq;
                strncpy(ifreq.ifr_name, ifa->ifa_name, IFNAMSIZ);
                if (ioctl(st->socket, SIOCGIFHWADDR, &ifreq) == -1) {
                    error = true;
                } else {
                    memcpy(&mac_address, &ifreq.ifr_hwaddr, sizeof(mac_address));
                    found = true;
                }
                break;
            }
            struct arpreq arpreq;
            memset(&arpreq, 0, sizeof(arpreq));
            memcpy(&(arpreq.arp_pa), &ip_address, sizeof(ip_address));
            strncpy(arpreq.arp_dev, ifa->ifa_name, IFNAMSIZ);
            if (ioctl(st->socket, SIOCGARP, &arpreq) == -1) {
                if (errno == ENXIO) {
                    continue;
                } else {
                    error = true;
                    break;
                }
            }
            if (arpreq.arp_flags & ATF_COM) {
                memcpy(&mac_address, &arpreq.arp_ha, sizeof(mac_address));
                found = true;
                break;
            }
        }
    }
cleanup:
    freeifaddrs(head_ifa);
    Py_END_ALLOW_THREADS
    if (error) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    if (found) {
        return mac_to_string((unsigned char *)mac_address.sa_data);
    }
    Py_RETURN_NONE;
}

/**
 * Try to import a module member given by name from a module given by name and
 * append it to a given list.
 *
 * ImportErrors are ignored.
 */
static int
try_import_member(PyObject *list, const char *module_name,
                      const char *member_name)
{
    PyObject *module = PyImport_ImportModule(module_name);
    if (!module) {
        if (PyErr_ExceptionMatches(PyExc_ImportError)) {
            PyErr_Clear();
            return 0;
        }
        return -1;
    }
    PyObject *member = PyObject_GetAttrString(module, member_name);
    Py_DECREF(module);
    if (!member) {
        return -1;
    }
    int success = PyList_Append(list, member);
    Py_DECREF(member);
    return success;
}

PyDoc_STRVAR(arpreq_doc,
"Translate IPv4 addresses to MAC addresses using the kernel's arp(7) interface."
);

static PyMethodDef arpreq_methods[] = {
    {"arpreq", arpreq, METH_O, arpreq_arpreq_doc},
    {NULL, NULL, 0, NULL}
};


/**
 * Execute the module
 */
static int
arpreq_exec(PyObject *module)
{
    PyObject *types = NULL;
    struct arpreq_state *st = GETSTATE(module);
    memset(st, 0, sizeof(*st));

    st->socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (st->socket == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto fail;
    }

    if (!(types = PyList_New(0))) {
        goto fail;
    }
    if (try_import_member(types, "ipaddr", "IPv4Address") == -1) {
        goto fail;
    }
    if (try_import_member(types, "ipaddress", "IPv4Address") == -1) {
        goto fail;
    }
    if (try_import_member(types, "netaddr", "IPAddress") == -1) {
        goto fail;
    }
    if (!(st->ipaddress_types = PySequence_Tuple(types))) {
        goto fail;
    }
    return 0;
fail:
    if (st->socket >= 0) {
        if (close(st->socket) == -1) {
#ifdef IS_PY3
            PyObject *type, *value, *traceback;
            PyErr_Fetch(&type, &value, &traceback);
            PyErr_NormalizeException(&type, &value, &traceback);
            Py_DECREF(type);
            Py_XDECREF(traceback);
            PyErr_SetFromErrno(PyExc_OSError);
            PyObject *type2, *value2, *traceback2;
            PyErr_Fetch(&type2, &value2, &traceback2);
            PyErr_NormalizeException(&type2, &value2, &traceback2);
            PyException_SetContext(value2, value);
            PyErr_Restore(type2, value2, traceback2);
#else
            PyErr_SetFromErrno(PyExc_OSError);
#endif
        }
    }
    Py_XDECREF(types);
    return -1;
}

#ifdef IS_PY3

/**
 * Free the module's resources.
 *
 * Closes the socket.
 */
static void
arpreq_free(void *m)
{
    struct arpreq_state *st = GETSTATE(m);
    if (st->socket >= 0) {
        close(st->socket);
    }
}


/**
 * Traverse the references this module holds during GC
 */
static int
arpreq_traverse(PyObject *m, visitproc visit, void *arg)
{
    Py_VISIT(GETSTATE(m)->ipaddress_types);
    return 0;
}


/**
 * Clear the module.
 */
static int
arpreq_clear(PyObject *m)
{
    Py_CLEAR(GETSTATE(m)->ipaddress_types);
    return 0;
}

#ifdef HAVE_PEP489
static PyModuleDef_Slot arpreq_slots[] = {
    {Py_mod_exec, arpreq_exec},
    {0, NULL},
};
#endif

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "arpreq",
        arpreq_doc,
        sizeof(struct arpreq_state),
        arpreq_methods,
#ifdef HAVE_PEP489
        arpreq_slots,
#else
        NULL,
#endif
        arpreq_traverse,
        arpreq_clear,
        arpreq_free
};

#  define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)
#  define MOD_SUCCESS(module) return module
#  define MOD_ERROR(module) { Py_XDECREF(module); return NULL; }
#else /* IS_PY3 */
#  define MOD_INIT(name) PyMODINIT_FUNC init##name(void)
#  define MOD_SUCCESS(module) return
#  define MOD_ERROR(module) return
#endif

/**
 * Initialize the arpreq module
 */
MOD_INIT(arpreq)
{
#ifdef HAVE_PEP489
    return PyModuleDef_Init(&moduledef);
#else
#  ifdef IS_PY3
    PyObject *module = PyModule_Create(&moduledef);
#  else
    PyObject *module = Py_InitModule3("arpreq", arpreq_methods, arpreq_doc);
#  endif
    if (module == NULL) {
        goto fail;
    }
    if (arpreq_exec(module) == -1) {
        goto fail;
    }
    MOD_SUCCESS(module);
fail:
    MOD_ERROR(module);
#endif /* HAVE_PEP489 */
}

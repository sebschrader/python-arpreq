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
#  if PY_VERSION_HEX >= 0x3030000
#    define IS_PY33
#  endif
#endif

struct arpreq_state {
    PyObject *ipaddress_types;
    int socket;
};

#ifdef IS_PY3
#define GETSTATE(m) ((struct arpreq_state*)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
static struct arpreq_state _state;
#endif

#ifdef IS_PY3
#  ifdef IS_PY33
#    define ASCIIString_New(size) PyUnicode_New(size, 127)
#    define ASCIIString_DATA(string) PyUnicode_DATA(string)
#  else
#    define ASCIIString_New(size) PyUnicode_FromStringAndSize(NULL, size)
#    define ASCIIString_DATA(string) PyUnicode_AS_DATA(string)
#  endif
#else
#  define ASCIIString_New(size) PyString_FromStringAndSize(NULL, size)
#  define ASCIIString_DATA(string) PyString_AS_STRING(string)
#endif

/**
 * Convert a binary MAC address into a lowercase Python str object.
 */
static inline PyObject *
mac_to_string(const unsigned char *eap)
{
    PyObject *string = ASCIIString_New(17);
    if (!string) {
        return NULL;
    }
    sprintf(ASCIIString_DATA(string), "%02x:%02x:%02x:%02x:%02x:%02x",
            (int) eap[0], (int) eap[1], (int) eap[2],
            (int) eap[3], (int) eap[4], (int) eap[5]);
    return string;
}

/**
 * Return the underlying buffer of Python str if interpreted as ASCII.
 *
 * If the Python str object does not store ASCII only data, the encoding of the
 * result is undefined.
 */
static inline const char *
as_ascii_data(PyObject *python_string)
{
#ifdef IS_PY33
    // Ensure that the string is in canonical form
    if (PyUnicode_READY(python_string) == -1) {
        return NULL;
    }
#endif
    return ASCIIString_DATA(python_string);
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


/**
 * Try to convert a Python str into an struct in_addr.
 *
 * The Python object must be a str object (unchecked).
 * Returns -1 on failure and 0 on success.
 */
static inline int
address_from_string(PyObject *object, struct in_addr *address)
{
    const char *ascii_string = as_ascii_data(object);
    if (!ascii_string) {
        return -1;
    }
    if (inet_pton(AF_INET, ascii_string, address) != 1) {
#ifdef IS_PY3
        PyErr_Format(PyExc_ValueError, "Invalid IPv4 address %U", object);
#else
        PyErr_Format(PyExc_ValueError, "Invalid IPv4 address %s", ascii_string);
#endif
        return -1;
    }
    return 0;
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
#ifdef IS_PY3
    if (PyUnicode_Check(object)) {
#else
    if (PyString_Check(object)) {
#endif
        return address_from_string(object, address);
    }
    if (PyObject_IsInstance(object, GETSTATE(self)->ipaddress_types)) {
        PyObject *python_string = PyObject_Str(object);
        if (!python_string) {
            return -1;
        }
        int result = address_from_string(python_string, address);
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
    ip_address.sin_family = AF_INET;
    memset(&(ip_address.sin_addr), 0, sizeof(ip_address));
    if (coerce_argument(self, arg, &(ip_address.sin_addr)) == -1) {
        return NULL;
    }

    uint32_t addr = ip_address.sin_addr.s_addr;
    bool error = false;
    bool found = false;
    struct sockaddr mac_address;
    struct ifaddrs *head_ifa;

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
        if ((ifaddr & netmask) == (addr & netmask)) {
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
int try_import_member(PyObject *list, const char *module_name,
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

#ifdef IS_PY3

/**
 * Free the module's resources.
 *
 * Closes the socket.
 */
static void
arpreq_free(void *m)
{
    close(GETSTATE(m)->socket);
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

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "arpreq",
        arpreq_doc,
        sizeof(struct arpreq_state),
        arpreq_methods,
        NULL,
        arpreq_traverse,
        arpreq_clear,
        arpreq_free
};

#  define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)
#  define MOD_SUCCESS(module) return module
#  define MOD_ERROR(module) { Py_XDECREF(module); return NULL; }
#else
#  define MOD_INIT(name) PyMODINIT_FUNC init##name(void)
#  define MOD_SUCCESS(module) return
#  define MOD_ERROR(module) return
#endif

/**
 * Initialize the arpreq module
 */
MOD_INIT(arpreq)
{
    PyObject *module = NULL;
    PyObject *types = NULL;
#ifdef IS_PY3
    module = PyModule_Create(&moduledef);
#else
    module = Py_InitModule3("arpreq", arpreq_methods, arpreq_doc);
#endif
    if (module == NULL) {
        goto fail;
    }
    struct arpreq_state *st = GETSTATE(module);

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
    Py_DECREF(types);
    MOD_SUCCESS(module);
fail:
    Py_XDECREF(types);
    MOD_ERROR(module);
}

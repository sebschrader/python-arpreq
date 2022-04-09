arpreq
======

.. image:: https://travis-ci.org/sebschrader/python-arpreq.svg?branch=master
    :target: https://travis-ci.org/sebschrader/python-arpreq
.. image:: https://img.shields.io/pypi/v/arpreq?cacheSeconds=2592000&style=for-the-badge
    :target: https://pypi.org/project/arpreq/
.. image:: https://img.shields.io/pypi/pyversions/arpreq?cacheSeconds=2592000&style=for-the-badge
    :target: https://pypi.org/project/arpreq/
.. image:: https://img.shields.io/pypi/implementation/arpreq?cacheSeconds=2592000&style=for-the-badge
    :target: https://pypi.org/project/arpreq/
.. image:: https://img.shields.io/pypi/wheel/arpreq?cacheSeconds=2592000&style=for-the-badge
    :target: https://pypi.org/project/arpreq/
.. image:: https://img.shields.io/pypi/l/arpreq?cacheSeconds=2592000&style=for-the-badge
    :target: https://pypi.org/project/arpreq/

Python C extension to query the Kernel ARP cache for the MAC address of
a given IP address.

Usage
-----

The ``arpreq`` module exposes two functions ``arpreq`` and ``arpreqb``, that
try to resolve a given IPv4 address into a MAC address by querying the ARP
cache of the Kernel.

An IP address can only be resolved to a MAC address if it is on the same
subnet as your machine.

Please note, that no ARP request packet is sent out by this module, only the
cache is queried. If the IP address hasn't been communicated with recently,
there may not be cache entry for it. You can refresh the cache, by trying to
communicate with IP (e.g. by sending and ICMP Echo-Request aka ping) before
probing the ARP cache.

Let's assume your current machine has the address ``192.0.2.10`` and
another machine with the address ``192.0.2.1`` is on the same subnet:

.. code:: python

    >>> import arpreq
    >>> arpreq.arpreq('192.0.2.1')
    '00:11:22:33:44:55'

If an IP address can not be resolved to an MAC address, None is returned.

.. code:: python

    >>> arpreq.arpreq('8.8.8.8') is None
    True

IP addresses may be also be specified as int or rich IP address data type
of the common ``ipaddr``, ``ipaddress``, or ``netaddr`` modules.

.. code:: python

    >>> arpreq.arpreq(0x7F000001)
    '00:00:00:00:00:00'
    >>> import netaddr
    >>> arpreq.arpreq(netaddr.IPAddress('127.0.0.1'))
    '00:00:00:00:00:00'
    >>> import ipaddr # on Python 2
    >>> arpreq.arpreq(ipaddr.IPv4Address('127.0.0.1'))
    '00:00:00:00:00:00'
    >>> import ipaddress
    >>> arpreq.arpreq(ipaddress.IPv4Address(u'127.0.0.1'))
    '00:00:00:00:00:00'

Instead of a hexadecimal string representation, MAC addresses may also be
returned as native bytes when using the ``arpreqb`` function:

.. code:: python

    >>> arpreq.arpreqb('127.0.0.1')
    b'\x00\x00\x00\x00\x00\x00'
    >>> arpreq.arpreqb('192.0.2.1')
    b'\x00\x11"3DU'

Supported Platforms
-------------------

This extension has only been tested on Linux, it should however work on
any platform that supports the ``SIOCGARP`` ioctl, which is virtually
every BSD and Linux. MacOS X does not work anymore, because Apple has
removed the interface.

IPv6-Support and Alternatives
-----------------------------

The ``SIOCGARP`` ioctl interface described in `arp(7)`_ and used by this
module is a fairly old mechanism and as the name suggests, works only for ARP
and therefore only for IPv4. For IPv6 the Linux Kernel uses the modern and
extensible `rtnetlink(7)`_ interface based on `netlink(7)`_ to manage
link-layer neighbor information.

Until Linux 5.0 however only whole tables could be dumped via `rtnetlink(7)`_
``RTM_GETNEIGH`` messages and it was not possible to query for specific IP
addresses. If entries need to be queried often or there are a lot of entries,
this might be too inefficient. As an optimization querying the tables only
once and subscribing to change events afterwards was possible, albeit more
complicated. Since
`Linux 5.0 <https://github.com/torvalds/linux/commit/24894bc6eabc43f55f5470767780ac07db18e797>`_
``RTM_GETNEIGH`` messages can be used to query specific addresses on specific
interfaces.

The pure-python netlink implementation `pyroute2`_ can be used to access the
`rtnetlink(7)`_ and other `netlink(7)`_ interfaces.
`Since version 0.5.14 <https://github.com/svinota/pyroute2/commit/b1f2af00689e17a50eb09b1560acfd0dc96b1a7a>`_
specific addresses can be queried.

.. _arp(7): https://manpages.debian.org/stable/manpages/arp.7.en.html
.. _netlink(7): https://manpages.debian.org/stable/manpages/netlink.7.en.html
.. _rtnetlink(7): https://manpages.debian.org/stable/manpages/rtnetlink.7.en.html
.. _pyroute2: https://pyroute2.org/

Changelog
---------

v0.3.4 (2021-12-21)
^^^^^^^^^^^^^^^^^^^
* Enable PEP-489 on PyPy3 5.8 and later
* Improve testing
* Move Debian packaging to separate branches
* Add docker-compose infrastructure for different manylinux variants
* Add ``arpreqb`` function, which returns the MAC as Python ``bytes`` object
* Support 8-byte/64-bit MAC addresses

v0.3.3 (2017-05-03)
^^^^^^^^^^^^^^^^^^^
* Disable PEP-489 on PyPy3
* Disable PyModule_GetState on PyPy3
* Provide a Debian package

v0.3.2 (2017-05-03)
^^^^^^^^^^^^^^^^^^^
* Support point-to-point veth pairs (See #6)
* Accept unicode objects on Python 2 and bytes objects on Python 3 (See #5)
* Some test improvements

v0.3.1 (2016-07-06)
^^^^^^^^^^^^^^^^^^^
* Don't use private _PyErr_ChainExceptions (breaks on Debian Jessie)

v0.3.0 (2016-06-26)
^^^^^^^^^^^^^^^^^^^

* Use PEP 489 multi-phase extension module initialization on Python 3.5+
* Close socket if module initialization failed
* Code cleanup

v0.2.1 (2016-06-26)
^^^^^^^^^^^^^^^^^^^
* Fix memset overflow

v0.2.0 (2016-06-09)
^^^^^^^^^^^^^^^^^^^

* Provide Python wheels
* Support int and rich IP address objects as IP address arguments
* Release the GIL during arpreq
* Add units tests
* Rework MAC string creation
* Restructure module initialization

v0.1.0 (2015-11-28)
^^^^^^^^^^^^^^^^^^^
* Initial release

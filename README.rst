arpreq
======

.. image:: https://travis-ci.org/sebschrader/python-arpreq.svg?branch=master
    :target: https://travis-ci.org/sebschrader/python-arpreq
.. image:: https://img.shields.io/pypi/v/arpreq.svg?maxAge=2592000
    :target: https://pypi.python.org/pypi/arpreq
.. image:: https://img.shields.io/pypi/pyversions/arpreq.svg?maxAge=2592000
    :target: https://pypi.python.org/pypi/arpreq
.. image:: https://img.shields.io/pypi/implementation/arpreq.svg?maxAge=2592000
    :target: https://pypi.python.org/pypi/arpreq
.. image:: https://img.shields.io/pypi/wheel/arpreq.svg?maxAge=2592000
    :target: https://pypi.python.org/pypi/arpreq
.. image:: https://img.shields.io/pypi/l/arpreq.svg?maxAge=2592000
    :target: https://pypi.python.org/pypi/arpreq

Python C extension to query the Kernel ARP cache for the MAC address of
a given IP address.

Usage
-----

The ``arpreq`` module exposes a single function ``arpreq``, that will
resolve a given IPv4 address into a MAC address.

An IP address can only be resolved to a MAC address if it is on the same
subnet as your machine.

Let's assume your current machine has the address ``192.168.1.10`` and
another machine with the address ``192.168.1.1`` is on the same subnet:

.. code:: python

    >>> import arpreq
    >>> arpreq.arpreq('192.168.1.1')
    '00:11:22:33:44:55'

If a IP address can not be resolved to an MAC address, None is returned.

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
    >>> import ipaddress # on Python 3
    >>> arpreq.arpreq(ipaddress.IPv4Address('127.0.0.1'))
    '00:00:00:00:00:00'

Supported Platforms
-------------------

This extension has only been tested on Linux, it should however work on
any platform that supports the ``SIOCGARP`` ioctl, which is virtually
every BSD, Linux and Mac OS.

Changelog
---------

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

arpreq
======

Python C extension to query the Kernel ARP cache for the MAC address of
a given IP address.

Usage
-----

The ``arpreq`` module exposes a single function ``arpreq``. This
functions expects an IPv4 address as a string.

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

Supported Platforms
-------------------

This extension has only been tested on Linux, it should however work on
any platform that supports the ``SIOCGARP`` ioctl, which is virtually
every BSD, Linux and Mac OS.

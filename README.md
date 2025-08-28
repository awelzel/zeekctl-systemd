zeekctl-systemd
===============

A [Zeekctl](https://github.com/zeek/zeekctl) plugin that hooks the install, start
and stop commands to use [systemd](https://systemd.io/) for process management
instead of starting Zeek processes using ``nohup`` and shell scripts.

Single-node Zeek cluster only at this point.

Limitations
-----------

Currently assumes ``node.cfg`` only contains worker, proxy and logger sections
that use ``host=localhost``. If you need multi-node support, that's probably
doable with Zeekctl's existing rsync infrastructure, but this isn't yet
supporting that.

This plugin by default requires a ``zeek`` user in a ``zeek`` group and
expects the ``spool/`` and ``logs/`` directories to be owned by ``zeek:zeek``.
However, ``zeekctl install`` needs to run as ``root``.

The post-terminate script only runs for logger processes, meaning crash
reports are likely not fully functional.

Quickstart
----------

    $ zkg install https://github.com/awelzel/zeekctl-systemd

    # Add systemd.enabled = True into zeekctl.cfg
    # Modify node.cfg as shown below.

    $ /opt/zeek/bin/zeekctl install

    # Check the created systemd unit files:
    $ ls -lha /usr/lib/systemd/system/zeek-*
    $ ls -lha /etc/systemd/system/zeek.target.wants/

    # Start all Zeek processes
    $ systemctl start zeek.target


    # Use systemd-cgtop to check on the processes
    $ systemd-cgtop zeek.slice

    # Check available plugin options with zeekctl config:
    s zeekctl config | grep ^systemd\.


TODO
----

* CPU pinning


node.cfg Example
----------------

Works nicest right now with AF_PACKET, a single interface and if your ``node.cfg``
looks something like the following. Note ``worker`` instead of ``worker-1`` for
nicer naming of the created systemd units.

    ## node.cfg
    [manager]
    type=manager
    host=localhost

    [logger-1]
    type=logger
    host=localhost

    [proxy-1]
    type=proxy
    host=localhost

    [proxy-2]
    type=proxy
    host=localhost

    [worker]
    type=worker
    host=localhost
    interface=enp7s0
    lb_method = af_packet
    lb_procs = 4



Per Node Environment Variables
------------------------------

In ``share/zeek/site/environment.d/``, place files named like the node,
e.g. ``logger-1`` or ``worker-1``. This can be used to override the environment
variables of the systemd unit files:

    # worker-1
    INTERFACE=eth0

    # worker-2
    INTERFACE=eth1

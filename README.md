zeekctl-systemd
===============

A [Zeekctl](https://github.com/zeek/zeekctl) plugin that hooks the install, start
and stop commands to use [systemd](https://systemd.io/) for process management
instead of starting Zeek processes using ``nohup`` and shell scripts.

Limitations
-----------

Currently assumes ``node.cfg`` only contains worker, proxy and logger sections
that use ``host=localhost``. If you need multi-node support, that's probably
doable with Zeekctl's existing rsync infrastructure, but I didn't have a use.

Quickstart
----------

    $ zkg install https://github.com/awelzel/zeekctl-systemd
    $ ... edit node.cfg ...
    $ /opt/zeek/bin/zeekctl install

    $ systemctl start zeek.target


Work nicest right now with AF_PACKET and if you ``node.cfg`` looks
something like this:

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

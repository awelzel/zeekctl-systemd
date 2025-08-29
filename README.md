zeekctl-systemd
===============

Run a Zeek cluster with systemd.

This is a [Zeekctl](https://github.com/zeek/zeekctl) plugin that hooks Zeekctl's
``install`` command in order to place [systemd](https://systemd.io/) unit files
onto the local system on which ``zeekctl`` runs. It further hooks ``start`` and ``stop``
commands to divert execution to the appropriate ``systemctl`` commands.

Essentially, this plugin supports you in running a Zeek cluster supervised by
systemd instead of Zeekctl's custom process management. Multi-node Zeek clusters
are out scope.

Quickstart
----------

    # Install this package
    $ zkg install https://github.com/awelzel/zeekctl-systemd

    # Modify zeekctl.cfg and add the following entry:
    systemd.enabled = 1

    # Ensure a zeek user and group exists and Zeek's spool/ and
    # logs/ directory is owned by that user.

    # Install the Zeek cluster's unit files onto the *local* system
    $ /opt/zeek/bin/zeekctl install

    # Check the created systemd unit files:
    $ ls -lha /usr/lib/systemd/system/zeek-*
    $ ls -lha /etc/systemd/system/zeek.target.wants/
    $ ls -lha /etc/systemd/system/zeek-*@*.d/*

    # Start the Zeek cluster (zeekctl start) would work too.
    $ systemctl start zeek.target

    # Stop the Zeek cluster
    $ systemctl start zeek.target

    # Restart individual Zeek processes
    $ systemctl restart zeek-logger@1 zeek-proxy@1 zeek-worker@4

    # Check on all of the cluster's processes
    $ systemd-cgtop zeek.slice


Implementation
--------------

This is a Zeekctl plugin. It uses the post install hook to render parametrized
unit files into ``/usr/lib/systemd/system`` for the individual Zeek process types.
Additionally, slices for logger, proxy and worker processes are created to cap
the total amount of memory a collection of these processes may consume.

The per-process configuration is done through override files in ``/etc/systemd/systemd/``.
For example, ``zeek-worker@1.service.d/99-zeekctl-override.conf`` has the following content:

    [Service]
    CPUAffinity=0
    Environment=INTERFACE=af_packet::enp7s0


Limitations
-----------

Currently assumes ``node.cfg`` only contains worker, proxy and logger sections
that use ``host=localhost``. If you need multi-node support, that's probably
doable with Zeekctl's existing rsync infrastructure, but it's unclear if that
is a feature that this plugin should ever support.

This plugin by default requires a ``zeek`` user in a ``zeek`` group and
expects the ``spool/`` and ``logs/`` directories to be owned by ``zeek:zeek``.
Note that ``zeekctl install`` needs to run as ``root`` for interaction with
systemd, however.

The post-terminate script only runs for logger processes, meaning crash
reports are not functional. Look into using ``coredumpctl``, it's likely
better integrated with your distribution.

Overriding
----------

Users can place override units into the per process directories ``/etc/systemd/system/``,
or use ``systemctl edit`` directly to place a ``override.conf`` file if per process
specific changes are to be made.

    $ systemctl edit zeek-manager

    $ systemctl edit zeek-worker@1

Testing in a Container
----------------------

The included [Dockerfile](./docker/Dockerfile) shows how to create a container
image that includes a bare-bones systemd installation and configures a Zeek cluster
with four workers within this container, listening on ``eth0``. Note that this
starts a privileged container!

    # Create the container image
    $ make container

    # Start the container in the backgroun
    $ make up

    # Enter the container or just run systmectl status within the running container.
    $ make enter
    $ make status


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



Available Plugin Options
------------------------

    $ zeekctl config | grep '^systemd\.'
    systemd.default_path = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    systemd.enabled = True
    systemd.etc_unit_path = /etc/systemd/system
    systemd.group = zeek
    systemd.lib_unit_path = /usr/lib/systemd/system
    systemd.logger_memory_max =
    systemd.logger_nice = -19
    systemd.loggers_memory_max =
    systemd.manager_memory_max =
    systemd.manager_nice = -19
    systemd.memory_max =
    systemd.proxies_memory_max =
    systemd.proxy_memory_max =
    systemd.proxy_nice = -19
    systemd.restart = always
    systemd.restart_sec = 1
    systemd.start_limit_interval_sec = 0
    systemd.user = zeek
    systemd.worker_memory_max =
    systemd.worker_nice = -19
    systemd.workers_memory_max =

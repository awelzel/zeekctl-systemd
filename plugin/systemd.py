import subprocess
import textwrap
import pathlib
import logging
import typing
import pwd
import grp
import os

import ZeekControl.cmdresult
import ZeekControl.config as config
import ZeekControl.plugin


class Systemd:
    """
    Minmal class for interacting with systemd.
    """

    logger = logging.getLogger("zeekctl.systemd")
    # logger.addHandler(logging.StreamHandler())

    def __init__(self, plugin):
        self.plugin = plugin
        self.bin = "systemctl"

        self.options = ["--no-page", "--no-ask-password"]

        # Keys to extract with show()
        self.show_keys = {
            "Id",
            "Name",
            "UnitFileState",
            "SubState",
            "ActiveState",
            "MainPID",
        }

    def systemctl(self, args):
        real_args = [self.bin, *self.options, *args]
        self.logger.debug("%s", " ".join(real_args))
        try:
            return subprocess.check_output(real_args)
        except subprocess.CalledProcessError as e:
            self.plugin.error(f"error starting: {e!r}")
            return None

    def enable(self, name, *, now=False):
        args = ["enable"]
        if now:
            args += ["--now"]
        args += [name]

        return self.systemctl(args)

    def start(self, units: typing.List[str]):
        self.systemctl(["start", *units])

    def stop(self, units: typing.List[str]):
        return self.systemctl(["stop", *units])

    def disable(self, name, *, now=False):
        args = ["disable"]
        if now:
            args += ["--now"]
        args += [name]
        return self.systemctl(args)

    def daemon_reload(self):
        return self.systemctl(["daemon-reload"])

    def show(self, args, *, all=True):
        """
        Helper to run `systemctl show <args>` and capture some interesting information per unit.
        """
        real_args = ["show"]
        if all:
            real_args += ["--all"]

        real_args += args

        output = self.systemctl(real_args).decode("utf-8")
        result = []
        current = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:  # empty line, new unit
                result += [current]
                current = {}
                continue

            k, v = line.split("=", 1)

            if k in self.show_keys:
                current[k] = v

        if current:
            result += [current]

        return result


class SystemdPlugin(ZeekControl.plugin.Plugin):
    def __init__(self):
        super().__init__(apiversion=1)
        self.sd = Systemd(self)

    def name(self):
        return "zeekctl-systemd"

    def prefix(self):
        return "systemd"

    def pluginVersion(self):
        return 1

    def init(self):
        self.enabled = self.getOption("enabled")
        if not self.enabled:
            return False

        if os.getuid() != 0:
            self.message(f"{self.prefix()}: not running as root will not work")

        self.spool_dir = pathlib.Path(self.getGlobalOption("spooldir"))
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.lib_unit_path = pathlib.Path(self.getOption("lib_unit_path"))
        self.zeek_bin = pathlib.Path(self.getGlobalOption("bindir")) / "zeek"
        self.bin_dir = pathlib.Path(self.getGlobalOption("bindir"))
        self.scripts_dir = pathlib.Path(self.getGlobalOption("scriptsdir"))
        self.env_file_common = self.spool_dir / "environment"

        self.env_file_d = (
            pathlib.Path(self.getGlobalOption("sitepolicypath")) / "environment.d"
        )
        self.env_file_d.mkdir(parents=True, exist_ok=True)

        # This is pretty annoything, but we cannot just extend PATH
        # within units wihout resorting to bash, so hard-code a
        # commonly used path here and render that via a Environment=PATH=...
        # entry in the respective unit files.
        self.default_path = self.getOption("default_path")
        self.path = ":".join(
            [str(self.bin_dir), str(self.scripts_dir), self.default_path]
        )

        # Filenames for unit files.
        self.zeek_target = self.lib_unit_path / "zeek.target"
        self.manager_unit = self.lib_unit_path / "zeek-manager.service"
        self.logger_unit = self.lib_unit_path / "zeek-logger@.service"
        self.proxy_unit = self.lib_unit_path / "zeek-proxy@.service"
        self.worker_unit = self.lib_unit_path / "zeek-worker@.service"
        self.loggers_slice = self.lib_unit_path / "zeek-loggers.slice"
        self.proxies_slice = self.lib_unit_path / "zeek-proxies.slice"
        self.workers_slice = self.lib_unit_path / "zeek-workers.slice"

        self.user = self.getOption("user")
        self.group = self.getOption("group")
        try:
            pwd.getpwnam(self.user)
        except KeyError:
            self.error(f"{self.prefix()}: configured user {self.user} not available")
        try:
            grp.getgrnam(self.group)
        except KeyError:
            self.error(f"{self.prefix()}: configured group {self.group} not available")

        if len(self.hosts()) > 1:
            self.message("Warning: No support for multiple hosts at this point.")

        return True

    def node_to_unit_id(self, node: ZeekControl.node.Node) -> str:
        """
        Returns the Id, e.g. zeek-manager.service, for a given node.
        """
        if node.type == "manager":
            return "zeek-manager.service"

        # worker-1-1 -> 1-1, worker-1 -> 1
        instance = node.name.split("-", 1)[-1]
        return f"zeek-{node.type}@{instance}.service"

    def options(self):
        return [
            ("enabled", "bool", False, "Set to enable plugin"),
            ("user", "string", "zeek", "The user to run Zeek under"),
            ("group", "string", "zeek", "The group to run Zeek under"),
            ("restart", "string", "on-failure", "They Restart= value to use"),
            ("restart_sec", "string", "1", "The RestartSec= value to use"),
            (
                "start_limit_interval_sec",
                "string",
                "0",
                "The StartLimitIntervalSec= value to use",
            ),
            (
                "default_path",
                "string",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "The default PATH used for running Zeek. bindir and scriptsdir will be prepended.",
            ),
            (
                "lib_unit_path",
                "string",
                "/usr/lib/systemd/system",
                "Directory for base and template systemd unit files.",
            ),
            (
                "manager_memory_max",
                "string",
                "",
                "Maximum memory allowed for the manager.",
            ),
            ("logger_memory_max", "string", "", "Maximum memory allowed per logger."),
            ("proxy_memory_max", "string", "", "Maximum memory allowed per proxy."),
            ("worker_memory_max", "string", "", "Maximum memory allowed per worker."),
            (
                "workers_memory_max",
                "string",
                "",
                "Maximum memory allowed for the workers slice.",
            ),
            (
                "loggers_memory_max",
                "string",
                "",
                "Maximum memory allowed for all loggers slice.",
            ),
            (
                "proxies_memory_max",
                "string",
                "",
                "Maximum memory allowed for all proxies slice.",
            ),
        ]

    def cmd_install_post(self):
        """
        Implement post installation steps to put unit files in place.

        After installing all scripts, render the systemd files, enable
        slices and unit instances. And disable those that aren't needed.
        """
        interface = None
        worker_interfaces = set([n.interface for n in config.Config.nodes("workers")])
        if len(worker_interfaces) == 1:
            interface = worker_interfaces.pop()
        else:
            # This can be implemented by placing per-worker environment files
            # into spool_dir/systemd/envirionment.d/worker-1-1 to override the
            # INTERFACE environment variable, but for AF_PACKET we don't need
            # this for now, so skip it.
            #
            # for wn in config.Config.nodes("workers"):
            #     print("wn", wn, dir(wn), wn.host, wn.name, wn.interface)
            #
            self.message("Warning: No support for per-worker interfaces at this point.")
            interface = "per-worker-interfaces-not-implemented"

        policydir_auto = self.getGlobalOption("policydirsiteinstallauto")
        policydir = pathlib.Path(self.getGlobalOption("policydir"))
        policydir_policy = policydir / "policy"
        policydir_site = policydir / "site"
        policydir_builtin_plugins = policydir / "builtin-plugins"

        # ZEEKPATH to use.
        zeekpath = ":".join(
            [
                policydir_auto,
                str(policydir),
                str(policydir_policy),
                str(policydir_site),
                str(policydir_builtin_plugins),
            ]
        )

        format_kwargs = {
            "user": self.getOption("user"),
            "group": self.getOption("group"),
            "spool_dir": self.spool_dir,
            "env_file_common": self.env_file_common,
            "env_file_d": self.env_file_d,
            "path": self.path,
            "zeek_bin": self.zeek_bin,
            "restart": self.getOption("restart"),
            "restart_sec": self.getOption("restart_sec"),
            "start_limit_interval_sec": self.getOption("start_limit_interval_sec"),
        }

        with self.zeek_target.open("w") as f:
            f.write(Units.zeek_target)

        with self.loggers_slice.open("w") as f:
            content = Units.loggers_slice.format(
                memory_max=self.getOption("loggers_memory_max"),
            )
            f.write(content)

        with self.proxies_slice.open("w") as f:
            content = Units.proxies_slice.format(
                memory_max=self.getOption("proxies_memory_max"),
            )
            f.write(content)

        with self.workers_slice.open("w") as f:
            content = Units.workers_slice.format(
                memory_max=self.getOption("workers_memory_max"),
            )
            f.write(content)

        with self.env_file_common.open("w") as f:
            f.write("# This file is auto-generated - do not modify\n")
            f.write(f"ZEEKPATH={zeekpath}\n")

        zeek_args = ["-U", ".status"]
        zeek_args += self.getGlobalOption("sitepolicyscripts").split()
        zeek_args += ["zeekctl/auto"]
        zeek_args += [self.getGlobalOption("zeekargs")]

        with self.manager_unit.open("w") as f:
            content = Units.manager_unit.format(
                zeek_args=" ".join(zeek_args),
                memory_max=self.getOption("manager_memory_max"),
                **format_kwargs,
            )
            f.write(content)

        with self.logger_unit.open("w") as f:
            content = Units.logger_unit_instance.format(
                zeek_args=" ".join(zeek_args),
                memory_max=self.getOption("logger_memory_max"),
                **format_kwargs,
            )
            f.write(content)

        with self.proxy_unit.open("w") as f:
            content = Units.proxy_unit_instance.format(
                zeek_args=" ".join(zeek_args),
                memory_max=self.getOption("proxy_memory_max"),
                **format_kwargs,
            )
            f.write(content)

        with self.worker_unit.open("w") as f:
            content = Units.worker_unit_instance.format(
                zeek_args=" ".join(zeek_args),
                interface=interface,
                memory_max=self.getOption("worker_memory_max"),
                **format_kwargs,
            )
            f.write(content)

        # XXX: We do not really need to do this if the files above haven't changed.
        self.sd.daemon_reload()

        expected_units = set()

        for node in config.Config.nodes():
            expected_units.add(self.node_to_unit_id(node))

        # Check for all units that are enabled right now and
        # disable those that we do not expect to be around
        # right away.
        live_units = self.sd.show(["zeek-*.service"])
        enabled_unit_ids = set(
            [lu["Id"] for lu in live_units if lu["UnitFileState"] == "enabled"]
        )
        for enabled_unit in enabled_unit_ids:
            if enabled_unit not in expected_units:
                self.sd.disable(enabled_unit, now=True)

        # Ensure the expected slices are enabled.
        expected_slices = {
            "zeek-workers.slice",
            "zeek-loggers.slice",
            "zeek-proxies.slice",
        }

        live_slices = set()
        for live_slice in self.sd.show(["zeek-*.slice"]):
            if live_slice["UnitFileState"] == "enabled":
                live_slices.add(live_slice["Id"])

        for expected_slice in expected_slices:
            if expected_slice not in live_slices:
                self.sd.enable(expected_slice, now=True)

        # Enable all units that aren't already enabled.
        for expected_unit in sorted(expected_units):
            if expected_unit not in enabled_unit_ids:
                self.sd.enable(expected_unit)

        # Create working now as the right user.
        dirs = [(node, node.cwd()) for node in config.Config.nodes()]
        for node, success, output in self.executor.mkdirs(dirs):
            if not success:
                self.error(f"cannot create working directory for {node.name}")

        cmds = [
            (node, "chown", ["-R", f"{self.user}:{self.group}", node.cwd()])
            for node in config.Config.nodes()
        ]
        for node, success, output in self.executor.run_cmds(cmds):
            if not success:
                self.error(f"cannot chown working directory for {node.name}")

    def cmd_start_pre(self, nodes):
        """
        Start all nodes on this system with systemd start.
        """
        for n in nodes:
            n.setExpectRunning(True)
            n.clearPID()
            n.clearCrashed()

        units = [self.node_to_unit_id(n) for n in nodes]
        self.sd.start(units)

        result = self.sd.show(units)
        pids = {r["Id"]: r["MainPID"] for r in result}
        for n in nodes:
            pid = pids[self.node_to_unit_id(n)]
            if pid != "0":
                n.setPID(pid)
            else:
                self.error(f"Zero pid for {n.name}")

        return []

    def cmd_start_post(self, results):
        """ """
        pass

    def cmd_stop_pre(self, nodes):
        """
        Stop all nodes via systemctl.
        """
        units = [self.node_to_unit_id(n) for n in nodes]
        self.sd.stop(units)
        for n in nodes:
            n.setExpectRunning(False)
            n.clearPID()
            n.clearCrashed()

        return nodes

    def cmd_stop_post(self, results):
        pass

    def cmd_status_pre(self, nodes):
        """
        Find the PID of all units from systemctl show and update
        the node status so it shows something nice.
        """
        units = [self.node_to_unit_id(n) for n in nodes]
        result = self.sd.show(units)
        result_by_id = {r["Id"]: r for r in result}
        for n in nodes:
            n.clearCrashed()

            unit_id = self.node_to_unit_id(n)
            pid = result_by_id[unit_id]["MainPID"]
            if pid != "0":
                n.setPID(pid)
            else:
                r = result_by_id[unit_id]
                state = r["ActiveState"]
                # If someone stopped a node with systemctl stop zeek-worker@3,
                # then it's state is inactive.
                if state == "inactive":
                    n.setExpectRunning(True)
                    n.clearPID()
                else:
                    n.setCrashed()


class Units:
    """
    Collection of systemd unit file templates.

    This is using just a few {variable} for templating in
    the strings that are then filled with a .format() call,
    nothing overly fancy here.
    """

    zeek_target = textwrap.dedent(
        """\
        [Unit]
        Description=The Zeek Network Security Monitor

        [Install]
        WantedBy=multi-user.target
        """
    )

    manager_unit = textwrap.dedent(
        """\
        [Unit]
        Description=Zeek Manager
        PartOf=zeek.target

        StartLimitIntervalSec={start_limit_interval_sec}

        [Service]
        User={user}
        Group={group}

        ReadWritePaths={spool_dir}/manager
        WorkingDirectory={spool_dir}/manager

        MemoryMax={memory_max}

        Environment=CLUSTER_NODE=manager
        EnvironmentFile={env_file_common}
        EnvironmentFile=-{env_file_d}/manager

        Environment=PATH={path}
        ExecStartPre=sh -c 'date +%%s > .startup'
        ExecStart={zeek_bin} {zeek_args}

        Slice=zeek-manager.slice

        Restart={restart}
        RestartSec={restart_sec}

        [Install]
        WantedBy=zeek.target
        """
    )

    logger_unit_instance = textwrap.dedent(
        """\
        [Unit]
        Description=Zeek Logger %i
        PartOf=zeek.target

        StartLimitIntervalSec={start_limit_interval_sec}

        [Service]
        User={user}
        Group={group}

        ReadWritePaths={spool_dir}/logger-%i
        WorkingDirectory={spool_dir}/logger-%i

        MemoryMax={memory_max}

        Environment=PATH={path}
        Environment=CLUSTER_NODE=logger-%i
        EnvironmentFile={env_file_common}
        EnvironmentFile=-{env_file_d}/logger-%i

        Environment=PATH={path}
        ExecStartPre=sh -c 'date +%%s > .startup'
        ExecStart={zeek_bin} {zeek_args}
        ExecStopPost=

        Slice=zeek-loggers.slice

        Restart={restart}
        RestartSec={restart_sec}

        [Install]
        WantedBy=zeek.target
        """
    )

    proxy_unit_instance = textwrap.dedent(
        """\
        [Unit]
        Description=Zeek Proxy %i
        PartOf=zeek.target

        StartLimitIntervalSec={start_limit_interval_sec}

        [Service]
        User={user}
        Group={group}

        ReadWritePaths={spool_dir}/proxy-%i
        WorkingDirectory={spool_dir}/proxy-%i

        MemoryMax={memory_max}

        Environment=CLUSTER_NODE=proxy-%i
        EnvironmentFile={env_file_common}
        EnvironmentFile=-{env_file_d}/proxy-%i

        Environment=PATH={path}
        ExecStartPre=sh -c 'date +%%s > .startup'
        ExecStart={zeek_bin} {zeek_args}

        Slice=zeek-proxies.slice

        Restart={restart}
        RestartSec={restart_sec}

        [Install]
        WantedBy=zeek.target
        """
    )

    worker_unit_instance = textwrap.dedent(
        """\
        [Unit]
        Description=Zeek Worker %i
        PartOf=zeek.target
        After=zeek-manager.service zeek-logger@.service zeek-proxy@.service

        StartLimitIntervalSec={start_limit_interval_sec}

        [Service]
        User={user}
        Group={group}

        CapabilityBoundingSet=CAP_NET_RAW
        AmbientCapabilities=CAP_NET_RAW

        MemoryMax={memory_max}

        WorkingDirectory={spool_dir}/worker-%i
        ReadWritePaths={spool_dir}/worker-%i

        EnvironmentFile={env_file_common}
        Environment=CLUSTER_NODE=worker-%i
        Environment=INTERFACE={interface}
        EnvironmentFile=-{env_file_d}/worker-%i

        Environment=PATH={path}
        ExecStartPre=sh -c 'date +%%s > .startup'
        ExecStart={zeek_bin} -i ${{INTERFACE}} {zeek_args}

        Slice=zeek-workers.slice

        Restart={restart}
        RestartSec={restart_sec}

        [Install]
        WantedBy=zeek.target
        """
    )

    workers_slice = textwrap.dedent(
        """\
        [Unit]
        PartOf=zeek.target

        [Slice]
        MemoryMax={memory_max}

        [Install]
        WantedBy=multi-user.target
        """
    )

    loggers_slice = textwrap.dedent(
        """\
        [Unit]
        PartOf=zeek.target

        [Slice]
        MemoryMax={memory_max}

        [Install]
        WantedBy=multi-user.target
        """
    )

    proxies_slice = textwrap.dedent(
        """\
        [Unit]
        PartOf=zeek.target

        [Slice]
        MemoryMax={memory_max}

        [Install]
        WantedBy=multi-user.target
        """
    )

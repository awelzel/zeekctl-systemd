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

logger = logging.getLogger("zeekctl.systemd")
# logger.addHandler(logging.StreamHandler())


class Systemd:
    """
    Minmal class for interacting with systemd through systemctl.
    """

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

    def systemctl(self, args, *, env=None, **kwargs):
        real_args = [self.bin, *self.options, *args]
        logger.debug("%s (env=%s)", " ".join(real_args), env)
        try:
            return subprocess.check_output(real_args, env=env, **kwargs)
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

        self.expected_slices = {
            "zeek.slice",
            "zeek-workers.slice",
            "zeek-loggers.slice",
            "zeek-proxies.slice",
        }

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
            self.error(
                f"{self.prefix()}: not running as root - will not work right now - sorry"
            )
            return False

        self.spool_dir = pathlib.Path(self.getGlobalOption("spooldir"))
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.lib_unit_path = pathlib.Path(self.getOption("lib_unit_path"))
        self.etc_unit_path = pathlib.Path(self.getOption("etc_unit_path"))
        self.zeek_bin = pathlib.Path(self.getGlobalOption("bindir")) / "zeek"
        self.bin_dir = pathlib.Path(self.getGlobalOption("bindir"))
        self.scripts_dir = pathlib.Path(self.getGlobalOption("scriptsdir"))
        self.zeek_base_dir = pathlib.Path(self.getGlobalOption("zeekbase"))

        # This is pretty annoything, but we cannot just extend PATH
        # within units wihout resorting to bash, so hard-code a
        # commonly used path here and render that via a Environment=PATH=...
        # entry in the respective unit files.
        self.default_path = self.getOption("default_path")
        self.path = ":".join(
            [str(self.bin_dir), str(self.scripts_dir), self.default_path]
        )

        # Paths to unit files in /usr/lib/systemd/system
        self.zeek_target = self.lib_unit_path / "zeek.target"
        self.zeek_slice = self.lib_unit_path / "zeek.slice"
        self.manager_service = self.lib_unit_path / "zeek-manager.service"
        self.logger_service = self.lib_unit_path / "zeek-logger@.service"
        self.proxy_service = self.lib_unit_path / "zeek-proxy@.service"
        self.worker_service = self.lib_unit_path / "zeek-worker@.service"
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

    def replace_if_different(self, p: pathlib.Path, content: str) -> bool:
        """
        Only replace p if content is different, return whether the file was replaced.
        """
        try:
            with p.open("r") as f:
                old_content = f.read()
                if old_content == content:
                    logger.debug("file %s is up-to-date", p)
                    return False  # early-exit
        except FileNotFoundError:
            pass

        logger.debug("Replacing %s", p)
        with p.open("w") as f:
            f.write(content)

        return True

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
                "etc_unit_path",
                "string",
                "/etc/systemd/system",
                "Directory for service override .d directories.",
            ),
            (
                "memory_max",
                "string",
                "",
                "Maximum memory allowed for the top-level zeek slice.",
            ),
            (
                "manager_memory_max",
                "string",
                "",
                "Maximum memory allowed for the manager.",
            ),
            ("manager_nice", "int", -19, "The default nice value to use for a manager"),
            ("logger_memory_max", "string", "", "Maximum memory allowed per logger."),
            ("logger_nice", "int", -19, "The default nice value to use for a logger"),
            ("proxy_memory_max", "string", "", "Maximum memory allowed per proxy."),
            ("proxy_nice", "int", -19, "The default nice value to use for a proxy"),
            ("worker_memory_max", "string", "", "Maximum memory allowed per worker."),
            ("worker_nice", "int", -19, "The default nice value to use for a worker"),
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

        zeek_args = ["-U", ".status"]
        zeek_args += self.getGlobalOption("sitepolicyscripts").split()
        zeek_args += ["zeekctl/auto"]
        zeek_args += [self.getGlobalOption("zeekargs")]

        format_kwargs = {
            "user": self.getOption("user"),
            "group": self.getOption("group"),
            "spool_dir": self.spool_dir,
            "etc_unit_path": self.etc_unit_path,
            "path": self.path,
            "zeek_bin": self.zeek_bin,
            "zeek_args": " ".join(zeek_args),
            "restart": self.getOption("restart"),
            "restart_sec": self.getOption("restart_sec"),
            "start_limit_interval_sec": self.getOption("start_limit_interval_sec"),
            "scripts_dir": self.scripts_dir,
            "zeek_base_dir": self.zeek_base_dir,
            "zeekpath": zeekpath,
        }

        # top-level zeek target
        sd_reload_needed = False
        sd_reload_needed |= self.replace_if_different(
            self.zeek_target, Units.zeek_target
        )

        # top-level zeek slice
        zeek_slice_content = Units.zeek_slice.format(
            memory_max=self.getOption("memory_max"),
        )
        sd_reload_needed |= self.replace_if_different(
            self.zeek_slice, zeek_slice_content
        )

        # loggers slice
        loggers_slice_content = Units.loggers_slice.format(
            memory_max=self.getOption("loggers_memory_max"),
        )
        sd_reload_needed |= self.replace_if_different(
            self.loggers_slice, loggers_slice_content
        )

        # proxies slice
        proxies_slice_content = Units.proxies_slice.format(
            memory_max=self.getOption("proxies_memory_max"),
        )
        sd_reload_needed |= self.replace_if_different(
            self.proxies_slice, proxies_slice_content
        )

        # workers slice
        workers_slice_content = Units.workers_slice.format(
            memory_max=self.getOption("workers_memory_max"),
        )
        sd_reload_needed |= self.replace_if_different(
            self.workers_slice, workers_slice_content
        )

        # manager unit
        manager_content = Units.manager_unit.format(
            type="manager",
            memory_max=self.getOption("manager_memory_max"),
            nice=self.getOption("manager_nice"),
            **format_kwargs,
        )
        sd_reload_needed |= self.replace_if_different(
            self.manager_service, manager_content
        )

        # logger unit
        logger_content = Units.logger_unit_instance.format(
            type="logger",
            memory_max=self.getOption("logger_memory_max"),
            nice=self.getOption("logger_nice"),
            **format_kwargs,
        )
        sd_reload_needed |= self.replace_if_different(
            self.logger_service, logger_content
        )

        # proxy unit
        proxy_content = Units.proxy_unit_instance.format(
            type="proxy",
            memory_max=self.getOption("proxy_memory_max"),
            nice=self.getOption("proxy_nice"),
            **format_kwargs,
        )
        sd_reload_needed |= self.replace_if_different(self.proxy_service, proxy_content)

        # worker unit
        worker_content = Units.worker_unit_instance.format(
            type="worker",
            memory_max=self.getOption("worker_memory_max"),
            nice=self.getOption("worker_nice"),
            **format_kwargs,
        )
        sd_reload_needed |= self.replace_if_different(
            self.worker_service, worker_content
        )

        # Now that the common units are in place, add override
        # directories into etc_unit_path / <unit>.d / zeekctl-override.conf
        #
        # This is used for a worker's interface and also the CPU pinning,
        # or if nodes have individual environment variables.
        for node in config.Config.nodes():
            unit_id = self.node_to_unit_id(node)

            override_p = self.etc_unit_path / f"{unit_id}.d" / "zeekctl-override.conf"
            override_p.parent.mkdir(parents=True, exist_ok=True)

            props = []
            if node.pin_cpus is not None and node.pin_cpus != "":
                props += [("CPUAffinity", int(node.pin_cpus))]

            if node.interface is not None and node.interface != "":
                props += [("Environment", f"INTERFACE={node.interface}")]

            for k, v in node.env_vars.items():
                props += [("Environment", f"{k}={v}")]

            service_content = "\n".join([f"{k}={v}" for (k, v) in props])

            content = textwrap.dedent(
                """\
            [Service]
            {service_content}
            """
            ).format(service_content=service_content)

            sd_reload_needed |= self.replace_if_different(override_p, content)

        # If any of the unit files has changed, toggle a daemon-reload.
        if sd_reload_needed:
            self.sd.daemon_reload()

        # All the units that we expect to be enabled on the system.
        expected_units = {self.node_to_unit_id(n) for n in config.Config.nodes()}
        logger.debug("expected systemd units: %s", sorted(expected_units))
        logger.debug("expected systemd slices: %s", sorted(self.expected_slices))

        # Check for all units that are enabled right now and
        # disable those that we do not expect to be around
        # right away.
        live_units = self.sd.show(["zeek-*.service"])
        enabled_unit_ids = set(
            [lu["Id"] for lu in live_units if lu["UnitFileState"] == "enabled"]
        )
        for enabled_unit in enabled_unit_ids:
            if enabled_unit not in expected_units:
                logger.debug("disabling unexpected unit %s", enabled_unit)
                self.sd.disable(enabled_unit, now=True)

        enabled_slices = set()
        for sl in self.sd.show(["zeek*.slice"]):
            if sl["UnitFileState"] == "enabled":
                enabled_slices.add(sl["Id"])

        for expected_sl in self.expected_slices:
            if expected_sl not in enabled_slices:
                self.sd.enable(expected_sl, now=True)

        # Enable all units that aren't already enabled. This
        # doesn't yet start them, but makes them available.
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

        Nice={nice}

        Environment=CLUSTER_NODE=manager

        Environment=PATH={path}
        Environment=ZEEKPATH={zeekpath}
        ExecStartPre=sh -c 'date +%%s > .startup'
        ExecStart={zeek_bin} {zeek_args}

        Slice=zeek.slice

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

        # The logger moves files from its spool directory into <base>/logs/<date>
        # so cannot limit ReadWritePaths to its spool directory.
        ReadWritePaths={zeek_base_dir}
        WorkingDirectory={spool_dir}/logger-%i

        MemoryMax={memory_max}

        Nice={nice}

        Environment=CLUSTER_NODE=logger-%i

        Environment=PATH={path}
        Environment=ZEEKPATH={zeekpath}
        ExecStartPre=sh -c 'date +%%s > .startup'
        ExecStart={zeek_bin} {zeek_args}

        # We don't have a crashflag, though we might be able to use EXIT_STATUS from systemd.
        ExecStopPost={scripts_dir}/post-terminate {type} {spool_dir}/logger-%i

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

        Nice={nice}

        Environment=CLUSTER_NODE=proxy-%i

        Environment=PATH={path}
        Environment=ZEEKPATH={zeekpath}
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

        Nice={nice}

        WorkingDirectory={spool_dir}/worker-%i
        ReadWritePaths={spool_dir}/worker-%i

        Environment=CLUSTER_NODE=worker-%i
        # INTERFACE is overridden in {etc_unit_path}/zeek-worker-<instance>.d/zeekctl-override.conf
        Environment=INTERFACE=

        Environment=PATH={path}
        Environment=ZEEKPATH={zeekpath}
        ExecStartPre=sh -c 'date +%%s > .startup'
        ExecStart={zeek_bin} -i ${{INTERFACE}} {zeek_args}

        Slice=zeek-workers.slice

        Restart={restart}
        RestartSec={restart_sec}

        [Install]
        WantedBy=zeek.target
        """
    )

    zeek_slice = textwrap.dedent(
        """\
        [Unit]
        PartOf=zeek.target

        [Slice]
        MemoryMax={memory_max}

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
        WantedBy=zeek.target
        """
    )

    loggers_slice = textwrap.dedent(
        """\
        [Unit]
        PartOf=zeek.target

        [Slice]
        MemoryMax={memory_max}

        [Install]
        WantedBy=zeek.target
        """
    )

    proxies_slice = textwrap.dedent(
        """\
        [Unit]
        PartOf=zeek.target

        [Slice]
        MemoryMax={memory_max}

        [Install]
        WantedBy=zeek.target
        """
    )

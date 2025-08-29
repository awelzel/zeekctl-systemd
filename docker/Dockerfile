# This is an example Dockerfile that sets up a Zeek cluster
# with zeekctl and systemd.
#
# Run with
#
#     docker run --name zeek-cluster --privileged tag zeek/zeek-dev-systemd
FROM zeek/zeek-dev

RUN apt-get update

RUN apt-get update && apt-get install -y --no-install-recommends systemd

RUN ln -s /lib/systemd/systemd /sbin/init

# Disable any systemd services, timers and mounts that
# we probably do not need within a container and are a
# bit dangerous to run within a privileged container.
#
# An alternative here is to use redhat/ubi10-init which
# is tailor-made for running systemd.
RUN systemctl mask \
	console-getty.service \
	dev-hugepages.mount \
	getty.target \
	modprobe.service \
	modprobe@.service \
	swap.target \
	dpkg-db-backup.timer \
	systemd-ask-password-console.path \
	systemd-ask-password-console.service \
	systemd-ask-password-wall.path \
	systemd-ask-password-wall.service \
	systemd-creds.socket \
	systemd-hostnamed.service \
	systemd-hostnamed.socket\
	systemd-initctl.socket \
	systemd-logind.service \
	systemd-machine-id-commit.service \
	systemd-random-seed.service \
	systemd-remount-fs.service \
	systemd-sysext.socket \
	systemd-tmpfiles-clean.timer \
	systemd-udev-trigger.service \
	systemd-udevd.service \
	systemd-user-sessions.service

# No mounts, please.
RUN cd /usr/lib/systemd/system/ && systemctl mask *.mount *automount

# No apt daily stuff!
RUN cd /usr/lib/systemd/system/ && systemctl mask apt-daily*

RUN cd /usr/lib/systemd/system/multi-user.target.wants && systemctl mask *service *.target
RUN cd /usr/lib/systemd/system/sysinit.target.wants && systemctl mask $(ls *.service *.target | grep -v systemd-journald.service)

STOPSIGNAL SIGRTMIN+3

RUN yes | zkg install https://github.com/awelzel/zeekctl-systemd

WORKDIR /usr/local/zeek

RUN useradd --system zeek

RUN echo "systemd.enabled = 1" >> etc/zeekctl.cfg

ARG interface=eth0
ARG lb_procs=4
ARG pin_cpus=

# There must be a better way!
RUN echo "\
[manager]\n\
host=localhost\n\
type=manager\n\
\n\n\
[logger-1]\n\
host=localhost\n\
type=logger\n\
\n\n\
[proxy-1]\n\
host=localhost\n\
type=proxy\n\
\n\n\
[worker]\n\
host=localhost\n\
type=worker\n\
lb_procs = ${lb_procs}\n\
lb_method = af_packet\n\
pin_cpus = ${pin_cpus}\n\
interface = ${interface}" > etc/node.cfg

# For local development
COPY plugin/systemd.py /usr/local/zeek/lib/zeek/plugins/packages/zeekctl-systemd

# Put systemd files in place.
RUN zeekctl install

CMD ["/sbin/init"]

import logging
from logging import handlers
import time
import sys
import os
import socket
from threading import Thread


def get_logger(verbosity=None):
    logger = logging.getLogger()
    if not verbosity:
        verbosity = 0
    loglevel = 50-verbosity*10
    logger.setLevel(loglevel)
    return logger


def configure_logging(logger, log_to_syslog=False):
    if log_to_syslog:
        syslog_log = handlers.SysLogHandler(address="/dev/log")
        log_format_syslog = logging.Formatter(time.strftime("%b %d %H:%M:%S") + " " +
                                              socket.gethostname() + " " +
                                              str("ResultWriter") + "[" +
                                              str(os.getpid()) + "]: " +
                                              "%(levelname)s %(message)s")
        syslog_log.setFormatter(log_format_syslog)
        logger.addHandler(syslog_log)
    else:
        console_log = logging.StreamHandler()
        log_format_console = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s')
        console_log.setFormatter(log_format_console)
        logger.addHandler(console_log)


def daemonize(stdin='/dev/null', stdout='/dev/null', stderr='/dev/null', pidfile_path="/var/run/monitunnel.pid"):
    # Fork process to detach from exec console
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Exit parent
    except OSError as e:
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    # Detach from parent environment
    os.chdir("/")
    os.umask(0)
    os.setsid()

    # Terminating the parent and continuing the daemon in the child
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    if os.path.isfile(pidfile_path):
        pidfile = open(pidfile_path, "r")
        pidfile.seek(0)
        oldpid = pidfile.readline()
        pidfile.close()
        sys.stderr.write("Pidfile found. Daemon with pid %s already running?\n" % (oldpid))

        sys.exit(1)
    else:
        pidfile = open(pidfile_path, "a+")
        pidfile.write(str(os.getpid()))
        pidfile.flush()
        pidfile.close()

    # Redirect standard file descriptors.
    s_in = open(stdin, 'r')
    s_out = open(stdout, 'a+')
    s_err = open(stderr, 'a+')
    os.dup2(s_in.fileno(), sys.stdin.fileno())
    os.dup2(s_out.fileno(), sys.stdout.fileno())
    os.dup2(s_err.fileno(), sys.stderr.fileno())

import argparse
import signal
import logging
from logging import handlers
import sys
import os
import time
from client.monitunnelclient import MonitunnelClient
import socket

parser = argparse.ArgumentParser(description="MoniTunnel client")
parser.add_argument("-a", "--address", help="Address of the monitutor server", metavar="x.x.x.x", required=True)
parser.add_argument("-p", "--port", default=13337, type=int, help="Port (default: %(default)s)")
parser.add_argument("-v", "--verbose", action="count", help="Increase verbosity")
parser.add_argument("-l", "--logging", action="store_true", help="Write messages to syslog instead of stdout. Increase verbosity of logs with -v")
parser.add_argument("-d", "--daemonize", action="store_true", help="Start in background")
parser.add_argument("-s", "--ssl", action="store_true", help="Enable SSL")
parser.add_argument("-u", "--username", required=True, help="Monitutor username")
parser.add_argument("-w", "--secret", required=True, help="Monitutor hmac-secret")
parser.add_argument("-n", "--hostname", required=True, help="Hostname of system")
parser.add_argument("-f", "--fqdn", default="example.net", required=False, help="Hostname of system")

config = vars(parser.parse_args())

clientThread = MonitunnelClient(config["username"],
                                config["hostname"],
                                config["secret"],
                                config["address"],
                                config["port"],
                                config["ssl"],
                                ssl_fqdn=config["fqdn"])


logger = logging.getLogger()
if not config["verbose"]:
    config["verbose"] = 0
loglevel = 50-config["verbose"]*10
logger.setLevel(loglevel)
if config["logging"]:
    syslog_log = handlers.SysLogHandler(address="/dev/log")
    log_format_syslog = logging.Formatter(time.strftime("%b %d %H:%M:%S") + " " +
            socket.gethostname() + " " +
            str("MoniTunnel") + "[" +
            str(os.getpid()) + "]: " +
            "%(levelname)s %(message)s")
    syslog_log.setFormatter(log_format_syslog)
    logger.addHandler(syslog_log)
else:
    console_log = logging.StreamHandler()
    log_format_console = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s')
    console_log.setFormatter(log_format_console)
    logger.addHandler(console_log)


def daemonize(stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    # Fork process to detach from exec console
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Exit parent
    except OSError, e:
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
    except OSError, e:
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    if os.path.isfile("/var/run/monitunnel.pid"):
        pidfile = open("/var/run/monitunnel.pid", "r")
        pidfile.seek(0)
        oldpid = pidfile.readline()
        pidfile.close()
        sys.stderr.write("Pidfile found. Daemon with pid %s already running?\n" % (oldpid))

        sys.exit(1)
    else:
        pidfile = open("var/run/monitunnel.pid", "a+")
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

def signal_handler(signum, frame):
    logging.warn("SIGNAL " + str(signum) + " received! Frame: " + str(frame))
    logging.debug("Stop Monitunnel thread")
    clientThread.stop()
    logging.debug("Wait for Monitunnel thread to join")
    clientThread.join()
    logging.debug("Monitunnel thread joined")
    if config["daemonize"]:
        os.remove("/var/run/monitunnel.pid")
    sys.exit(0)

if "__main__" == __name__:
    if config["daemonize"]:
        daemonize()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGALRM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logging.debug("Start Monitunnel Thread")
    clientThread.start()

    run = True

    while run:
        time.sleep(1)


import argparse
import signal
import logging
import sys
import os
import time

parser = argparse.ArgumentParser(description="MoniTunnel server")
parser.add_argument("-a", "--address", default="0.0.0.0", help="Address to listen to", metavar="x.x.x.x")
parser.add_argument("-p", "--port", default=13337, type=int, help="Listening port (default: %(default)s)")
parser.add_argument("-v", "--verbose", action="count", help="Increase verbosity")
parser.add_argument("-l", "--logging", action="store_true", help="Write messages to syslog instead of stdout. Increase verbosity of logs with -v")
parser.add_argument("-d", "--daemonize", action="store_true", help="Start as daemon")
parser.add_argument("-s", "--ssl", action="store_true", help="Enable and enforce SSL")

config = vars(parser.parse_args())
print config

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
    logging.warn("SIGNAL" + str(signum) + "received! Frame:" + str(frame))
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

    run = True

    while run:
        time.sleep(1)


import argparse
import signal
import logging
import sys
import os
import time
from client.monitunnelclient import MonitunnelClient
from utils import configure_logging
from utils import daemonize
from utils import get_logger

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


logger = get_logger(config["verbose"])
configure_logging(logger, config["logging"])


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

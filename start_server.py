import argparse
import signal
import logging
import sys
import os
import time
from server.monitunneldaemon import MoniTunnelDaemon
from utils import configure_logging
from utils import daemonize
from utils import get_logger

parser = argparse.ArgumentParser(description="MoniTunnel server")
parser.add_argument("-a", "--address", default="0.0.0.0", help="Address to listen to", metavar="x.x.x.x")
parser.add_argument("-p", "--port", default=13337, type=int, help="Listening port (default: %(default)s)")
parser.add_argument("-v", "--verbose", action="count", help="Increase verbosity")
parser.add_argument("-l", "--logging", action="store_true", help="Write messages to syslog instead of stdout. Increase verbosity of logs with -v")
parser.add_argument("-d", "--daemonize", action="store_true", help="Start as daemon")
parser.add_argument("-s", "--ssl", action="store_true", help="Enable and enforce SSL")
parser.add_argument("-u", "--db-user", help="Database user")
parser.add_argument("-w", "--db-password",  help="Database password")
parser.add_argument("-j", "--db-host", default="localhost", help="Address of the database host")
parser.add_argument("-n", "--db-name", default="monitutor", help="Name of the database")
parser.add_argument("-r", "--rabbit-mq-host", default="localhost", help="Address of the rabbit-mq server")

config = vars(parser.parse_args())

daemon = MoniTunnelDaemon(port=config["port"],
                          address=config["address"],
                          rabbit_result_exchange="result_exchange",
                          rabbit_task_exchange="task_exchange",
                          rabbit_host=config["rabbit_mq_host"],
                          db_engine="postgresql",
                          db_host=config["db_host"],
                          db_password=config["db_password"],
                          db_database=config["db_name"],
                          db_username=config["db_user"])

logger = get_logger(config["verbose"])
configure_logging(logger, config["logging"])


def signal_handler(signum, frame):
    logging.warn("SIGNAL " + str(signum) + " received! Frame: " + str(frame))
    logging.debug("Stop Monitunnel thread")
    daemon.stop()
    logging.debug("Wait for Monitunnel thread to join")
    daemon.join()
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
    daemon.start()
    run = True
    while run:
        time.sleep(1)

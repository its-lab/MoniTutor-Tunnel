import argparse
import logging
import signal
import time
from server.icinga2_resultwriter import IcingaResultWriter as ResultWriter
import sys
import os
from utils import daemonize
from utils import configure_logging
from utils import get_logger

parser = argparse.ArgumentParser(description="MoniTunnel server")
parser.add_argument("-a", "--rabbit-mq-host", default="localhost", help="Address of the rabbit-mq server")
parser.add_argument("-v", "--verbose", action="count", help="Increase verbosity. -vvvvv == DEBUG")
parser.add_argument("-l", "--logging", action="store_true", help="Write messages to syslog instead of stdout. Increase verbosity of logs with -v")
parser.add_argument("-t", "--task-exchange", default="task_exchange", help="Name of the task exchange")
parser.add_argument("-r", "--result-exchange", default="result_exchange", help="Name of the result exchange")
parser.add_argument("-d", "--daemonize", action="store_true", help="Start as daemon")
parser.add_argument("-i", "--icinga-path", default="/var/run/icinga2/cmd/icinga2.cmd", help="Absolut path to icinga2.cmd file")

config = vars(parser.parse_args())

result_writer = ResultWriter(config["rabbit_mq_host"],
                             config["result_exchange"],
                             config["task_exchange"],
                             config["icinga_path"])

logger = get_logger(config["verbose"])
configure_logging(logger, config["logging"])


def signal_handler(signum, frame):
    logging.warn("SIGNAL " + str(signum) + " received! Frame: " + str(frame))
    logging.debug("Stop ResultWriter thread")
    result_writer.stop()
    logging.debug("Wait for ResultWriter thread to join")
    result_writer.join()
    logging.debug("ResultWriter thread joined")
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
    logging.debug("Start Icinga ResultWriter Thread")
    result_writer.start()
    run = True
    while run:
        time.sleep(1)

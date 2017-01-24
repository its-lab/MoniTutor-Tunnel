#!/usr/bin/python
from __future__ import print_function
import time
import socket
import os
import logging
import threading
from socket import error as socket_error
import argparse
import json
import subprocess
import re
import signal
import sys
import ssl
import hashlib
import base64
import hmac
import tempfile


#################
#   Usage       #
#################
parser = argparse.ArgumentParser(
        description="MoniTunnel client script.",
        epilog="To use the MoniTunnel application you also need to run the server.\n"
               "MoniTunnel does not support IPv6 yet.")
parser.add_argument("-a", "--address", required=True, help="Server IPv4 address")
parser.add_argument("-p", "--port", default=13337, type=int, help="Server port (default: %(default)s)")
parser.add_argument("-v", "--verbose", action="count", help="Increase verbosity")
parser.add_argument("-l", "--log", action="store_true", help="Enable logging to syslog")
parser.add_argument("-u", "--user", type=str, default="anonymous",
        help="Username (default: %(default)s)")
parser.add_argument("-n", "--hostname", type=str, help="[Optional]")
parser.add_argument("-s", "--secret", type=str, default="nosecret", help="Secret user password [Optional]")


args = parser.parse_args()

verbose = False
syslog_enabled = False


loglevel = "CRITICAL"
if args.verbose > 0:
    verbose = args.verbose
    if args.verbose == 1:
        loglevel = "WARNING"
    elif args.verbose == 2:
        loglevel = "INFO"
    else:
        loglevel = "DEBUG"


if args.log is True:
    syslog_enabled = True

# Globals

TMPDIR       = tempfile.mkdtemp()
check_filenames = {} # {"checkname": "/path/to/check/script"}

host = args.address
port = args.port
user = args.user
secret = "nosecret"
server_address = (host, port)

if args.secret is not None:
    secret = args.secret

if args.hostname is None:
    hostname = socket.gethostname()
else:
    hostname = args.hostname

identifier = user + "_" + hostname

if not os.path.exists(TMPDIR):
    os.mkdir(TMPDIR)


# Logger

logger = logging.getLogger("MoniTunnel")
numeric_loglevel = getattr(logging, loglevel)
if not isinstance(numeric_loglevel, int):
    raise ValueError('Invalid log level: %s' % loglevel)
logger.setLevel(numeric_loglevel)

if verbose:
    console_log = logging.StreamHandler()
    console_log.setLevel(numeric_loglevel)
    log_format_console = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s')
    console_log.setFormatter(log_format_console)
    logger.addHandler(console_log)

request_queue = []
answer_queue = []

socket_closed = threading.Event()
socket_open = threading.Event()
socket_closed.set()
socket_open.clear()

request_queue_sema = threading.Semaphore(0)
answer_queue_sema = threading.Semaphore(0)


class Init(threading.Thread):

    def __init__(self):
        super(Init, self).__init__()
        self.__run = True

    def stop(self):
        self.__run = False
        try:
            self.client_socket.shutdown(socket.SHUT_RDWR)
        except AttributeError as err:
            logger.exception(err)

    def _connect(self):
        threshold = 300
        attempts = 1
        done = False

        while not done and self.__run:
            try:
                logger.info("Connecting to Server " + str(server_address))
                self.client_socket = socket.create_connection(timeout=2, address=server_address)
                self.client_socket = ssl.wrap_socket(self.client_socket)
                self.client_socket.setblocking(0)
                self.client_socket.settimeout(60.0)
                done = True
            except socket_error as s_err:
                attempts += 1
                logger.warn("Connection to server " + str(host) + ":" + str(port) + " failed. " +
                            str(s_err) + " - Try (" + str(attempts) + "/" + str(threshold) + ")")
                if attempts < threshold:
                    time.sleep(6)
                else:
                    logger.critical("Unable to connect to server: " + str(server_address))
                    return False
            except Exception as err:
                logger.critical("Unexpected exception caught:" + str(err))
                return False
        return True

    def run(self):
        connected = self._connect()
        while connected and self.__run:
            readthread = Read(socket=self.client_socket)
            readthread.start()

            writethread = Write(socket=self.client_socket)
            writethread.start()
            try:
                task = (1, 100)
                status_dict = {"task": task, "result": {"host": identifier}, "code": "NEW"}
                answer_queue.append(status_dict)
                answer_queue_sema.release()
                socket_open.set()
                socket_closed.clear()
                logger.debug("Thread waits for socket errors, to restart socket")
                socket_closed.wait()
                logger.debug("Thread wakes up after Socket error. Reinitialize socket.")
                self.client_socket.close()
                time.sleep(1)

                logger.debug("Join socket_read thread")
                readthread.stop()
                readthread.join()
                del readthread

                logger.debug("Join socket_write thread")
                writethread.stop()
                answer_queue_sema.release()
                writethread.join()
                del writethread

                time.sleep(5)
                connected = self._connect()

            except Exception as err:
                logger.exception("Exception! " + str(err) + " Reinitialize socket.")
                readthread.stop()
                readthread.join()
                del readthread

                writethread.stop()
                answer_queue_sema.release()
                writethread.join()
                del writethread

                connected = self._connect()
        return True


class Read(threading.Thread):

    def __init__(self, socket):
        super(Read, self).__init__()
        self.socket = socket
        self.__run = True

    def sock_receive(self, last_chunk):
        chunks = []
        eos = False
        next_chunk = ""
        payload = []
        while not eos and self.__run:
            chunk = self.socket.recv(512)
            logger.debug("chunk received. " + str(len(chunk)) + "-" + str(chunk))
            if chunk == "":
                raise socket.error(" Socket connection broken")
            else:
                match_first = re.search(pattern='^["]?[\]]*[\}]+', string=chunk)
                match_last = re.search(pattern='$[^\\\]["]?[\]]*[\}]*', string=last_chunk)
                match = re.search(pattern='([^\\\]["][\]]*[\}]+)', string=chunk)

                if match_first and match_last:  # was there an EOS-beginning at the end of the last receive?
                    chunks.append(chunk[:match_first.end()])
                    next_chunk = chunk[match_first.end():]
                    eos = True
                    payload.append(''.join(chunks))
                    return {"payload": payload, "next_chunk": next_chunk}

                elif not match:
                    chunks.append(chunk)
                else:
                    while match:
                        logger.debug("EOS detected. Append " + str(chunk[:match.end()]))
                        chunks.append(chunk[:match.end()])
                        if len(chunk) == match.end():
                            payload.append(''.join(chunks))
                            chunks = []
                        elif chunk[match.end()] != ",":
                            payload.append(''.join(chunks))
                            chunks = []
                        if len(chunk) > match.end():
                            next_chunk = chunk[match.end():]
                        match = re.search(pattern='([^\\\]["][\]]*[\}]+)', string=next_chunk)
                        if match:
                            chunk = next_chunk
                            next_chunk = ""
                    eos = True
        return {"payload": payload, "next_chunk": next_chunk}

    def stop(self):
        self.__run = False

    def run(self):
        threshold = 3
        tries = 1
        next_chunk = ""
        while self.__run:
            try:
                logger.debug("reading socket")
                message = self.sock_receive(next_chunk)
                logger.debug("Message received:" + str(message))
                results = message["payload"]
                results[0] = next_chunk+results[0]
                next_chunk = message["next_chunk"]

                if results is not None:
                    try:
                        for result in results:
                            status_dict = json.loads(result)
                            if "ERROR" in status_dict:
                                logger.critical("Received ERROR msg from Server: "+status_dict["ERROR"])
                                raise ValueError
                            logger.debug("request_queue.append(" + str(status_dict) + ")")
                            request_queue.append(status_dict)
                            tries = 0
                            request_queue_sema.release()

                    except ValueError as err:
                        logger.exception(err)
                        socket_closed.set()
                        self.__run = False

                    except Exception as err:
                        logger.exception(err)
                        socket_closed.set()
                        self.__run = False

            except socket.timeout:
                logger.info("Socket Timeout while reading. Try again [" + str(tries) +
                            "/" + str(threshold) + "]")
                if threshold <= tries:
                    logger.info("Socket probably down. Restart Socket")
                    socket_closed.set()
                    self.__run = False
                tries += 1

            except socket.error as err:
                logger.error("Socket Error:" + str(err))
                socket_closed.set()
                self.__run = False


class Write(threading.Thread):

    def __init__(self, socket):
        super(Write, self).__init__()
        self.socket = socket
        self.__run = True

    def stop(self):
        self.__run = False

    def run(self):
        while self.__run:
            answer_queue_sema.acquire()
            if not self.__run:
                return
            status_dict = answer_queue.pop()
            packet = {"message": "", "HMAC": " ", "ID": user}
            serialized_msg = json.dumps(status_dict)
            status_dict_hmac = hmac.new(secret, str(serialized_msg), hashlib.sha256).hexdigest()
            packet["HMAC"] = status_dict_hmac
            packet["message"] = serialized_msg
            serialized_packet = json.dumps(packet)
            successfully_send = False
            while not successfully_send:
                try:
                    logger.debug("Try to send status dictionary serialized:" + str(serialized_packet))
                    self.socket.send(serialized_packet)
                    logger.debug("Dictionary sent successfully.")
                    successfully_send = True
                except socket_error:
                    answer_queue.append(status_dict)
                    answer_queue_sema.release()
                    socket_open.clear()
                    socket_closed.set()
                    socket_open.wait()


class Check(threading.Thread):

    def __init__(self):
        super(Check, self).__init__()
        self.__run = True

    def stop(self):
        self.__run = False
        request_queue_sema.release()

    def run(self):
        while self.__run:
            logger.debug("Check_thread tries to acquire request_queue.")
            request_queue_sema.acquire()
            if not self.__run:
                return
            check = request_queue.pop()
            logger.debug("Acquired check: " + str(check))

            if "code" in check:
                try:
                    logger.info("Creating new check file")
                    newtempfile = tempfile.mkstemp(dir=TMPDIR)
                    check_filenames[check["task"][5]] = newtempfile[1]
                    newcheck = open(newtempfile[1], "w+")
                    newcheck.writelines(check["code"].replace("\r\n","\n"))
                    newcheck.flush()
                    newcheck.close()
                    os.chmod(newtempfile[1], 0755)
                    if not os.path.isfile(newtempfile[1]):
                        logger.error("File creation failed")
                    del check["code"]
                    request_queue.append(check)
                    request_queue_sema.release()

                except:
                    check["code"] = "FAIL"
                    answer_queue.append(check)
                    answer_queue_sema.release()

            else:
                execthread = Execute(check)
                execthread.start()
                execthread.join()


class Execute(threading.Thread):

    def __init__(self, check):
        super(Execute, self).__init__()
        self.check = check
        self.__run = True

    def stop(self):
        self.__run = False

    def run(self):
        if not self.__run:
            return
        try:
            exists = False
            if self.check["task"][5] in check_filenames:
                tempfile_name = check_filenames[self.check["task"][5]]
                exists = os.path.isfile(tempfile_name)
            if not exists:
                raise IOError("Check file not available")
            elif exists:
                programfile = open(tempfile_name, "rb")
                code_string = programfile.read()
                code_hash = hashlib.sha256(code_string)
                code_hash = code_hash.digest()
                code_hash = base64.urlsafe_b64encode(code_hash)
                if code_hash != self.check["task"][6]:
                    logger.error("Execute thread: Hash " + code_hash + "didn't match" + self.check["task"][6])
                    logger.debug("CODE that was hashed:" + code_string)
                    raise IOError("Check file not up to date or modified")
        except IOError:
            self.check["code"] = "REQUEST"
            answer_queue.append(self.check)
            answer_queue_sema.release()
            return

        try:
            checkline = self.check["task"][4] + " " \
                + tempfile_name
            if self.check["task"][3] is not None:
                checkline += " " + self.check["task"][3]
            logger.info("Execute: " + str(checkline))
            checkOut = subprocess.check_output(checkline, stderr=subprocess.STDOUT, shell=True)
            checkCode = 0
        except subprocess.CalledProcessError as checkExc:
            checkOut = checkExc.output
            checkCode = checkExc.returncode
            logger.warn("Execution failed: " + str(checkOut).strip("\n").strip("\r").strip("\l") + ". Code = " + str(checkCode))

        logger.info("Execution result: " + str(checkOut).strip("\n").strip("\r").strip("\l") + ". Code = " + str(checkCode))
        if "result" not in self.check:
            self.check["result"] = {}
        self.check["result"]["time"] = str(int(time.time()))
        self.check["result"]["code"] = checkCode
        self.check["result"]["short"] = checkOut
        self.check["result"]["host"] = identifier
        self.check["result"]["type"] = "PROCESS_SERVICE_CHECK_RESULT"
        self.check["result"]["username"] = user
        answer_queue.append(self.check)
        answer_queue_sema.release()
        return


if "__main__" == __name__:
    logger.info("Starting MoniTunnel as " + identifier)

    i = Init()
    i.start()

    c = Check()
    c.start()

    def signal_handler(signum, frame):
        logger.warn("SIGNAL" + str(signum) + "received! Frame:" + str(frame))
        logger.warn("Stopping " + str(c))
        c.stop()
        c.join()
        logger.warn("Stopping " + str(i))
        i.stop()
        i.join()

        sys.exit(0)

    run = True
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGALRM, signal_handler)

    while run:
        time.sleep(1)


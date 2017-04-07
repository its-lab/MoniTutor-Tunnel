from __future__ import print_function
import sys
import time
import threading
import socket
import logging
from logging import handlers
import Queue as Qu
import argparse
import pykka
import datetime
import json
import signal
import os
import re
import copy
import db
import ssl
import hashlib
import base64
import hmac


if os.name == 'posix' and sys.version_info[0] < 3:
    import subprocess32 as subprocess
else:
    import subprocess

#################
#   Constants   #
#################
ICINGACMD = "/var/run/icinga2/cmd/icinga2.cmd"
#################
#   GLOBALS     #
#################

checkqueues = dict()            # dict, that contains a unique host, queue pair, where queue contains checks

#################
#   Usage       #
#################

parser = argparse.ArgumentParser(
        description="MoniTunnel server script.",
        epilog="To use the MoniTunnel application you also need to run the client.")
parser.add_argument("-a", "--address", help="Address to listen to", metavar="x.x.x.x")
parser.add_argument("-p", "--port", default=13337, type=int, help="Listening port (default: %(default)s)")
parser.add_argument("-v", "--verbose", action="count", help="Increase verbosity")
parser.add_argument("-l", "--log", action="count", help="Increase Logging level. Overwrites verbose.")
parser.add_argument("-d", "--daemonize", action="store_true", help="Start as daemon")
parser.add_argument("-i", "--insecure", action="store_true",
                    help="Disable client message authentication. Not recommended")

args = parser.parse_args()

if args.address:
    host = args.address
else:
    host = ""

port = args.port

logger = logging.getLogger("MoniTunnel")
def init_logging():
    loglevel = "CRITICAL"
    syslog_enabled = False
    verbose = False
    if args.verbose > 0:
        verbose = args.verbose
        if args.verbose == 1:
            loglevel = "WARNING"
        elif args.verbose == 2:
            loglevel = "INFO"
        else:
            loglevel = "DEBUG"

    if args.log > 0:
        syslog_enabled = True
        if args.log == 1:
            loglevel = "WARNING"
        elif args.log == 2:
            loglevel = "INFO"
        else:
            loglevel = "DEBUG"

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

    if syslog_enabled:
        syslog_log = handlers.SysLogHandler(address="/dev/log")
        syslog_log.setLevel(numeric_loglevel)
        log_format_syslog = logging.Formatter(time.strftime("%b %d %H:%M:%S") + " " +
                                              socket.gethostname() + " " +
                                              str("MoniTunnel") + "[" +
                                              str(os.getpid()) + "]: " +
                                              "%(levelname)s %(message)s")
        syslog_log.setFormatter(log_format_syslog)
        logger.addHandler(syslog_log)


dbHandle = db.Session()


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


class QueueHandler(pykka.ThreadingActor):

    def __init__(self, resultwriter=None):
        super(QueueHandler, self).__init__()
        self._checkqueues = {}
        self.resultwriter = resultwriter
        self._run = True
        # init code with access to start() arguments

    def _addtoqueue(self, task):
        logger.debug("QueueHandler._addtoqueue(" + str(task) + ")")
        if isinstance(task, db.Check_tasks):
            identifier = task.username+"_"+task.hostname
            if identifier not in self._checkqueues:
                self._checkqueues[identifier] = Qu.PriorityQueue()
            logger.debug("add new task:" + str(task))
            program = dbHandle.query(db.Programs).filter(db.Programs.name.like(task.program_name)).first()
            logger.debug("code: " + program.code)
            program_hash = hashlib.sha256(program.code.replace("\r\n","\n"))  # Hashes the program code
            program_hash = base64.urlsafe_b64encode(program_hash.digest())  # encodes the hash with base64
            logger.debug("_addtoqueue will add " + str((task.check_tasks_id, task.prio, task.check_name,
                                               task.parameters, task.interpreter_path, task.program_name,
                                               program_hash)) + " to " + identifier + "'s queue")
            self._checkqueues[identifier].put((task.check_tasks_id, task.prio, task.check_name,
                                               task.parameters, task.interpreter_path, task.program_name, program_hash))

            return True
        return False

    def _update_loop(self):
        while self._run:
            self._updatequeue()
            time.sleep(1)
        return True

    def _updatequeue(self):
        logger.debug("QueueHandler._updatequeue started")
        tasks = dbHandle.query(db.Check_tasks).filter(db.Check_tasks.status.like("NEW")).\
                order_by(db.Check_tasks.prio, db.Check_tasks.timestamp)
        for task in tasks:
            self._addtoqueue(task)
            dbHandle.query(db.Check_tasks).filter(db.Check_tasks.check_tasks_id == task.check_tasks_id)\
                                          .update({"status": "QUEUED", "timestamp": datetime.datetime.now()},
                                                  synchronize_session='fetch')
        return True

    def _updatedb(self, task):
        logger.debug("QueueHandler._updatedb started, set 'ASSIGNED' for:" + str(task))
        dbHandle.query(db.Check_tasks).filter(db.Check_tasks.check_tasks_id == task[0])\
                                      .update({"status": "ASSIGNED", "timestamp": datetime.datetime.now()},
                                              synchronize_session='fetch')
        return True

    def on_start(self):
        logger.info("QueueHandler started -" + str(self))
        newthread = threading.Thread(target=self._update_loop)
        newthread.start()

    def on_stop(self):
        logger.info("Queuehandler stopped  " + str(self))
        return True

    def on_receive(self, message):
        logger.debug("QueueHandler received message: " + str(message))

        if isinstance(message, dict):
            if "add" in message and "identifier" in message:
                if message.get("identifier") not in self._checkqueues:
                    self._checkqueues[message.get("identifier")] = Qu.PriorityQueue()
                self._checkqueues[message.get("identifier")].put(message.get("add"))
            elif "identifier" not in message:
                if "stop" in message:
                    self._run = False
                else:
                    logger.warn('[WARNING Queuehandler_rcv] No identifier given! ' + str(message))
            else:
                logger.debug("Looking for Queue, matching " + str(message["identifier"]))
                if message["identifier"] in self._checkqueues:
                    logger.debug("Queue for identifier " + str(message["identifier"]) + " found.")
                    queue = self._checkqueues[message["identifier"]]
                    if isinstance(queue, Qu.PriorityQueue):
                        if not queue.empty():
                            task = queue.get()
                            self._updatedb(tuple(task))
                            task = {"task": task}
                            logger.debug("Queue(" + str(message["identifier"]) + ") is not empty. " + str(task))
                        else:
                            task = False
                            logger.debug("Queue(" + str(message["identifier"]) + ") is empty.")

                        return task
                else:
                    return None


class Resultwriter(pykka.ThreadingActor):

    def __init__(self, args=None):
        super(Resultwriter, self).__init__()
        # dbHandle = db.Session()
        self._icingacmd = ICINGACMD

        # init code with access to start() arguments

    def _updatedb(self, task):
        dbHandle.query(db.Check_tasks).filter(db.Check_tasks.check_tasks_id == task[0])\
                            .update({"status": "DONE", "timestamp": datetime.datetime.now()},
                                    synchronize_session='fetch')
        return True

    def _restarttasks(self):
        logger.debug("Resetting all Assigned tasks in database.")
        dbHandle.query(db.Check_tasks).filter(
            db.Check_tasks.status.like("ASSIGNED"),
            (datetime.datetime.now()-db.Check_tasks.timestamp) >= datetime.timedelta(seconds=30)).update(
            {"status": "NEW", "timestamp": datetime.datetime.now()}, synchronize_session='fetch')
        return True


    # expects: {"result":{
    #           "time": int(time.time())
    #           "typ": "PROCESS_SERVICE_CHECK_RESULT",
    #           "host": "ms5366s_client",
    #           "name": "testservice",
    #           "code": 1,
    #           "short": "OK - All Fine"
    #           },
    #           "task":(
    #           )
    # }
    def on_receive(self, message):
        logger.debug("resultwriter received message:" + str(message))
        if "reset" in message:
            self._restarttasks()
        if "result" in message:
            result = message["result"]
            if "time" in result \
                and "type" in result \
                and "host" in result \
                and "username" in result \
                and "code" in result \
                and "short" in result:
                resultstring = "["+result.get("time") + "] "
                resultstring += result.get("type") + ";"
                resultstring += result.get("host") + ";"
                if result.get("type") == "PROCESS_SERVICE_CHECK_RESULT":
                    resultstring += result.get("username") + "_"
                    resultstring += message["task"][2] + ";"
                resultstring += str(result.get("code")) + ";"
                resultstring += result.get("short").replace("\n", "").replace("\r","")


                commandline = "echo '" + resultstring + "' >> "+self._icingacmd+";"
                logger.info("Execute:" + str(resultstring))
                try:
                    subprocess.check_output(
                                            commandline,
                                            shell=True)
                    if "task" in message:
                        task = message["task"]
                        self._updatedb(tuple(task))
                except subprocess.CalledProcessError as checkExc:
                    checkOut = checkExc.output
                    checkCode = checkExc.returncode
                    logger.critical(str(commandline) + "FAILED" + str(checkOut) + ", Returncode: " + str(checkCode))
                    writers = pykka.ActorRegistry.get_by_class(Resultwriter)
                    if len(writers):
                        writers[0].tell({"add": message["task"], "identifier": message["result"]["username"]})

            else:
                logger.error("Missing Elements in Resultmsg:" + str(result))
                writers = pykka.ActorRegistry.get_by_class(Resultwriter)
                if len(writers):
                    writers[0].tell({"add": message["task"], "identifier": message["result"]["username"]})

        return True

    def on_stop(self):
        self._restarttasks()
        logger.info("Resultwriter stopped -" + str(self))
        return True


class ServerThread(pykka.ThreadingActor):

    def __init__(self, resultwriter=None, queuehandle=None):
        super(ServerThread, self).__init__()
        self.resultwriter = resultwriter
        self.queuehandle = queuehandle
        self.__daemonthread = None
        self.__run = True

    def on_stop(self):
        logger.info("Stopping Server Actor" + str(self))
        if self.__run:
            self.set_run()
        del self._sock

    def _daemon(self):
        socket_opened = False
        tries = 0
        threshold = 10

        while self.__run and not socket_opened:
            if tries > threshold:
                sys.exit()
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind((host, port))
                self._sock = ssl.wrap_socket(self._sock, server_side=True, keyfile="/etc/ssl/key.pem", certfile="/etc/ssl/cert.pem", ciphers="HIGH")
                self._sock.listen(0)
                socket_opened = True
            except socket.error:
                logger.warn("Socket error... Waiting 10 seconds to retry.")
                del self._sock
                time.sleep(10)
                tries += 1

        logger.info("Server is listening for incoming connections. Try to connect to " + str(host) + ":" + str(port))

        try:
            while self.__run:
                try:
                    self._sock.settimeout(2)
                    new_connection = self._sock.accept()
                    new_client = new_connection[0]
                    logger.info("New Client: " + str(new_client))
                    for actor in pykka.ActorRegistry.get_by_class(ClientThread):
                        actorinfo = actor.ask({"info": "short"})
                        if not actorinfo["running"]:
                            actor.stop()
                except socket.timeout:
                    time.sleep(1)
                    if self.__run:
                        continue
                    else:
                        break
                except ssl.SSLError as err:
                    logger.exception("Exception caught" + str(err))
                    if self.__run:
                        continue
                    else:
                        break
                except socket.error as err:
                    logger.exception("exception caught" + str(err))
                    if self.__run:
                        continue
                    else:
                        break

                if self.__run:
                    new_actor = ClientThread().start(new_client, queuehandle=self.queuehandle, resultwriter=self.resultwriter)
                    logger.info("Incoming Connection. Thread started. " + str(new_actor))
                else:
                    new_client.shutdown(socket.SHUT_RDWR)
                    del new_client

        except Exception as err:
            logger.exception("Exception caught" + str(err))
            for actor in pykka.ActorRegistry.get_by_class(ClientThread):
                actor.ask({"stop": True})
                actor.stop()
            self._sock.close()

    def on_start(self):
        self.__daemonthread = threading.Thread(target=self._daemon)
        self.__daemonthread.start()
        return True

    def set_run(self):
        if self.__run:
            self.__run = False
        else:
            self.__run = True

    def on_receive(self, message):
        if "stop" in message:
            self.__run = False
            logger.info("Stop Server -" + str(self.__run))
            self.__daemonthread.join()
            logger.info("Daemon thread stopped")
            self.stop()
            return True


class ClientThread(pykka.ThreadingActor):

    def __init__(self, socket=None, queuehandle=None, resultwriter=None):
        super(ClientThread, self).__init__()
        self._socket = socket
        self._identifier = None
        self._username = None
        self.__hmac_secret = None
        self._heartbeat = 10
        self.resultwriter = resultwriter
        self.queuehandle = queuehandle
        self.__pulling = False
        self.threadlist = []
        self.__run = True
        self._last_command = None
        self._last_success = None

    def sock_receive(self, last_chunk):
        chunks = []
        eos = False
        next_chunk = ""
        payload = []
        while not eos:
            chunk = self._socket.recv(512)
            logger.debug("chunk received. " + str(len(chunk)) + "-" + str(chunk))
            if chunk == "":
                raise socket.error("Socket connection broken")
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
                    logger.debug("Append chunk to chunks")
                    chunks.append(chunk)
                else:
                    while match:
                        logger.debug("EOS detected. Append " + str(chunk[:match.end()]))
                        chunks.append(chunk[:match.end()])
                        if len(chunk) == match.end():
                            logger.debug("CHUNK ENDS HERE. APPEND")
                            payload.append(''.join(chunks))
                            chunks = []
                        elif chunk[match.end()] != ",":
                            logger.debug("CHUNKS END != , " + chunk[match.end()] + ". APPEND")
                            payload.append(''.join(chunks))
                            chunks = []
                        if len(chunk) > match.end():
                            logger.debug("Buffer rest of chunk " + str(chunk[match.end():]))
                            next_chunk = chunk[match.end():]
                        match = re.search(pattern='([^\\\]["][\]]*[\}]+)', string=next_chunk)
                        if match:
                            chunk = next_chunk
                            next_chunk = ""
                    eos = True
        return {"payload": payload, "next_chunk": next_chunk}

    def _readsocket(self):
        logger.debug("ClientThread._readsocket started. Socket-ID:" + str(self._socket))
        next_chunk = ""
        while self.__run:
            try:
                message = self.sock_receive(next_chunk)
                logger.debug("Message received:" + str(message))
                results = message["payload"]
                if len(results):
                    results[0] = next_chunk+results[0]
                next_chunk = message["next_chunk"]

            except socket.error as err:
                logger.error("Socket Error " + str(err))
                if self.__run  and self.__pulling:
                    self.__run = False
                    self.__pulling = False
                    self.stop()
                break

            if len(results):
                for result in results:
                    try:
                        status_packet = json.loads(result)
                        logger.debug("Result after json.loads: " +
                                str(status_packet))
                        try:
                            if "HMAC" in status_packet and "ID" in status_packet:
                                if self._username is None:
                                    self._username = status_packet["ID"]
                                    userRow = dbHandle.query(db.Auth_user).filter(db.Auth_user.username
                                            == self._username).first()
                                    logger.debug(str(userRow))
                                    self.__hmac_secret = str(userRow.hmac_secret)
                                    logger.debug("HMAC of user " +
                                            self._username + " = " +
                                            self.__hmac_secret)
                                elif self._username != status_packet["ID"]:
                                    raise ValueError("UserID changed")

                                result_hmac = hmac.new( self.__hmac_secret,
                                        str(status_packet["message"]),
                                                        hashlib.sha256).hexdigest()
                                if result_hmac == status_packet["HMAC"]:
                                    logger.debug("HMAC match")
                                else:
                                    raise ValueError("HMAC didnt't match - unauthenticated user!")
                            else:
                                raise ValueError("No HMAC found - unauthenticated user!")
                        except Exception as err:
                            if args.insecure:
                                logger.info("Message auth failed but was ignored")
                            else:
                                logger.exception("Exception: " + str(err))
                                logger.critical("Unauthorized access from " +
                                        str(self._socket.getpeername()) + " witth  ID: " + status_packet["ID"])
                                self._writesocket({"ERROR": "Authentication failed"})
                                self.__run = False
                                self.__polling = False
                                self.stop()
                                break

                        status_dict = json.loads(status_packet["message"])
                        if "code" in status_dict:
                            task = status_dict.get("task")
                            if status_dict["code"] == "NEW":
                                self._identifier = status_dict["result"]["host"]
                                logger.info("New identifier! " + str(self._identifier))
                                if self.__pulling is False:
                                    self.__pulling = True
                                    pulling_thread = threading.Thread(target=self._puller)
                                    pulling_thread.start()
                                    self.threadlist.append(pulling_thread)

                            elif status_dict["code"] == "FAIL":
                                logger.error("Check failed. Write FAIL into check table." + str(status_dict["task"]))
                                dbHandle.query(db.Check_tasks).filter(db.Check_tasks.check_tasks_id == task[0])\
                                                              .update(
                                    {"status": "FAIL", "timestamp": datetime.datetime.now()},
                                    synchronize_session='fetch'
                                    )

                            elif status_dict["code"] == "REQUEST":
                                logger.debug(self._identifier + "requested" + str(status_dict["task"][5]) +
                                             ". Sending code.")
                                del status_dict["code"]
                                newthread = threading.Thread(target=self._sendprogram, args=[dict(status_dict),])
                                newthread.start()

                        else:
                            if self.resultwriter is not None:
                                logger.debug("send RESULT to resultwriter" + str(status_dict))
                                self._last_success = status_dict
                                self.resultwriter.tell(status_dict)
                                logger.debug("generate HOST_CHECK_RESULT for id: " + self._identifier +
                                             "and send to resultwriter.")
                                host_dict = copy.deepcopy(status_dict)
                                host_dict["result"]["type"] = "PROCESS_HOST_CHECK_RESULT"
                                host_dict["result"]["short"] = "Connected"
                                host_dict["result"]["code"] = 0
                                self.resultwriter.tell(host_dict)

                    except Exception as err:
                        logger.exception("Exception caught: " + str(err) + " - " + str(result))
                        self.__run = False
                        break
        self.__pulling = False

    def _writesocket(self, task):
        logger.debug("ClientThread._writesocket started, task: " + str(task))
        serialized_dict = json.dumps(task)
        logger.debug("serialized task after json.dumps: " + str(task))
        successfully_send = False
        while not successfully_send and self.__run:
            try:
                self._socket.send(serialized_dict)
                self._last_command = task
                return True
            except socket.error as err:
                logger.warn("Socket error (" + self._identifier + ") caught: " + str(err))
                return False
        return False

    def _sendprogram(self, task):
        programs = dbHandle.query(db.Programs).filter(db.Programs.name.like(task["task"][5]))\
            .filter(db.Checks.name.like(task["task"][2]))
        programcode = programs[0].code
        task["code"] = programcode
        done = False
        tries = 0
        while not done and tries < 3 and self.__run:
            done = self._writesocket(task)
            tries += 1
        return

    def _pulltask(self):
        if self.queuehandle and self.__pulling:
            logger.debug(self._identifier + " asks Queuehandler for new tasks")
            task = self.queuehandle.ask({"identifier": self._identifier})

            if not task:
                logger.debug(self._identifier + " - No task available")
                return False
            logger.debug(self._identifier + "calls writesocket(" + str(task) + ")")
            done = False
            tries = 0
            while not done and tries < 3 and self.__run:
                try:
                    done = self._writesocket(task)
                except:
                    tries += 1
            return True
        return False

    def _puller(self):
        while self.__pulling:
            result = self._pulltask()
            if not result:
                time.sleep(5)

    def on_start(self):
        self._newmail = False
        a = threading.Thread(target=self._readsocket)
        a.start()
        self.threadlist.append(a)
        return True

    def on_stop(self):
        self.__run = False
        self.__pulling = False
        self._socket.shutdown(socket.SHUT_RDWR)
        for thread in self.threadlist:
            thread.join()
            self.threadlist.remove(thread)
            del thread
        self._socket.close()
        del self._socket
        logger.info("Clientthread: " + self._identifier + str(self) + "Stopped.")
        return True

    def on_receive(self, message):
        if "info" in message:
            if message["info"] == "short":
                return {"identifier": self._identifier, "pulling": self.__pulling, "running": self.__run}
            elif message["info"] == "all":
                return {"identifier": self._identifier, "pulling": self.__pulling, "running": self.__run,
                        "last_command": self._last_command, "last_success": self._last_success}

        elif "stop" in message:
            self.__pulling = False
            self.__run = False
            logger.info("Stop Client - run:" + str(self.__run) + " pulling:" + str(self.__pulling))
            self.stop()
            return True



if "__main__" == __name__:
    if args.daemonize:
        daemonize("/dev/null", "/dev/null", "/dev/null")
    init_logging()
    resultwriter = Resultwriter.start()
    queuehandle = QueueHandler.start(resultwriter=resultwriter)
    server = ServerThread.start(resultwriter=resultwriter, queuehandle=queuehandle)



    def signal_handler(signum, frame):
        logger.warn("SIGNAL" + str(signum) + "received! Frame:" + str(frame))

        for actor in pykka.ActorRegistry.get_all():
            logger.warn(str(actor))
        for actor in pykka.ActorRegistry.get_by_class(ClientThread):
            logger.warn("Trying to kill Actor " + str(actor))
            actor.ask({"stop": True})
        for actor in pykka.ActorRegistry.get_by_class(ServerThread):
            logger.warn("Trying to kill Actor " + str(actor))
            actor.ask({"stop": True})
        for actor in pykka.ActorRegistry.get_by_class(QueueHandler):
            logger.warn("Trying to kill Actor " + str(actor))
            actor.ask({"stop": True})
            actor.stop()
        for actor in pykka.ActorRegistry.get_by_class(Resultwriter):
            logger.warn("Trying to kill Actor " + str(actor))
            actor.stop()
        if args.daemonize:
            os.remove("/var/run/monitunnel.pid")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGALRM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    run = True

    while run:
        time.sleep(1)

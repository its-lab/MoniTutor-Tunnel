import subprocess
import logging
from threading import Thread
from threading import Semaphore
from threading import Event
import socket
from Queue import Queue
import json
import hashlib
import hmac
import time
from re import search
import tempfile
import ssl
import base64


class MonitunnelClient(Thread):

    def __init__(self, username, hostname, hmac_secret, server_address, server_port=13337, ssl_enabled=False, ssl_cert="cert.pem", ssl_fqdn="example.com"):
        super(MonitunnelClient, self).__init__()
        self.__running = False
        self.__connected = False
        self._username = username
        self._hostname = hostname
        self._hmac_secret = hmac_secret
        self._server_socket_config = (server_address, server_port)
        self._identifier = username+"."+hostname
        self._socket_receive_thread = Thread(target=self._socket_receive, name="receive")
        self._socket_send_thread = Thread(target=self._socket_send, name="send")
        self._message_processing_thread = Thread(target=self._process_messages, name="send")
        self._message_inbox = Queue()
        self._message_outbox = Queue()
        self._pending_checks = {}
        self._socket_opened = Event()
        self._socket_closed = Event()
        self._socket_opened.clear()
        self._message_inbox_lock = Semaphore(0)
        self._message_outbox_lock = Semaphore(0)
        self._program_file_names = {}
        self._program_checksums = {}
        self._tmp_dir = tempfile.mkdtemp()
        self._ssl_enabled = ssl_enabled
        self._ssl_cert = ssl_cert
        self._ssl_fqdn = ssl_fqdn
        if self._ssl_enabled:
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.load_verify_locations(self._ssl_cert)

    def run(self):
        self.__running = True
        self._socket_receive_thread.start()
        self._socket_send_thread.start()
        self._message_processing_thread.start()
        while self.__running:
            self._socket_closed.clear()
            counter = 1
            while self.__running and not self.__connected:
                self.__connected = self._connect_to_server()
                if not self.__connected:
                    time.sleep(2)
                    logging.info("Wasn't able to connect to server. Try "+str(counter)+"...")
                    counter += 1
            if self.__running:
                self._socket_opened.set()
                self._authenticate()
                self._socket_closed.wait()
                self.__connected = False
                time.sleep(.5)

    def _authenticate(self):
        message = {"method": "auth", "body": self._hostname}
        self.send_message(message)

    def send_message(self, message):
        logging.debug("Send message to server: "+str(message))
        self._message_outbox.put(message)
        self._message_outbox_lock.release()

    def _socket_receive(self):
        self._socket_opened.wait()
        chunk_buffer = ""
        while self.__running:
            try:
                chunk = self._socket.recv(1024)
                if chunk == "":
                    raise socket.error("empty message")
            except (socket.error, ssl.SSLError) as err:
                if err.message == "timed out" or err.message == "The read operation timed out":
                    pass
                else:
                    logging.exception("socket error while receive")
                    self._socket_opened.clear()
                    self._socket_closed.set()
            else:
                messages, chunk_buffer = self._get_message_from_chunks(chunk, chunk_buffer)
                for message in messages:
                    self._message_inbox.put(message)
                    self._message_inbox_lock.release()
            if self.__running:
                self._socket_opened.wait()

    def _get_message_from_chunks(self, chunk, chunk_buffer):
        messages = []
        while search('[^\x03]*\x03', chunk):
            end_of_message = search('[^\x03]*\x03', chunk)
            messages.append(chunk_buffer+end_of_message.group(0)[:-1].strip("\x02"))
            chunk_buffer = ""
            if len(chunk) > end_of_message.end(0):
                chunk = chunk[end_of_message.end(0)+1:].strip("\x02")
            else:
                chunk = ""
        else:
            chunk_buffer += chunk.strip("\x02")
        return (messages, chunk_buffer)

    def _process_messages(self):
        self._message_inbox_lock.acquire()
        while self.__running:
            message = self._message_inbox.get()
            message = json.loads(message)
            logging.debug("New message from server:"+ str(message))
            if message["message"]["method"] == "task":
                self._process_check(message["message"]["body"])
            elif message["message"]["method"] == "request_program":
                self._save_program(message["message"]["body"])
            self._message_inbox_lock.acquire()

    def _process_check(self, check_info):
        logging.debug("Process check:" +str(check_info))
        result = self._execute_check(check_info)
        logging.debug("check prcocessed. Result: "+str(result))
        if result:
            self._add_attachments(check_info, result)
            result["check"] = check_info
            result = {"method": "result", "body": result}
            self.send_message(result)

    def _add_attachments(self, check, result):
        if "attachments" in check:
            attachments = []
            for attachment_spec in check["attachments"]:
                if "requires_status" not in attachment_spec \
                  or attachment_spec["requires_status"] == result["severity_code"]:
                    attachments.append(self._create_attachment(attachment_spec))
            result["attachments"] = attachments
        return True

    def _create_attachment(self, attachment_spec):
        attachment = {"name": attachment_spec["name"]}
        producer_temp_file_handle = tempfile.mkstemp(dir=self._tmp_dir)
        produce_file = open(producer_temp_file_handle[1], "w+")
        subprocess.call(attachment_spec["producer"],
                        stdout=produce_file,
                        shell=True)
        produce_file.flush()
        produce_file.close()
        result_file_handle = producer_temp_file_handle[1]
        if "filter" in attachment_spec:
            filter_temp_file_handle = tempfile.mkstemp(dir=self._tmp_dir)
            filtered_file = open(filter_temp_file_handle[1], "w+")
            produce_file = open(producer_temp_file_handle[1], "r")
            subprocess.call(attachment_spec["filter"],
                            stdin=produce_file,
                            stdout=filtered_file,
                            shell=True)
            filtered_file.flush()
            filtered_file.close()
            result_file_handle = filter_temp_file_handle[1]
        result_file = open(result_file_handle, "r")
        attachment["data"] = base64.b64encode(result_file.read())
        return attachment

    def _execute_check(self, check_info):
        if self._program_is_available(check_info["program"]):
            return self.execute(check_info)
        else:
            logging.debug("Program "+str(check_info["program"])+" is not available")
            self.send_message({"method": "request_program", "body": check_info["program"]})
            if check_info["program"] not in self._pending_checks.keys():
                self._pending_checks[check_info["program"]] = Queue()
            self._pending_checks[check_info["program"]].put(check_info)
            return False

    def _program_is_available(self, program_name):
        if program_name in self._program_file_names.keys():
            with open(self._program_file_names[program_name], "rb") as program:
                code_string = program.read()
                try:
                    if self._get_checksum(code_string) == self._program_checksums[program_name]:
                        return True
                except KeyError:
                    return False
        return False

    def execute(self, check_info):
        logging.debug("execute "+str(check_info))
        program_path = self._program_file_names[check_info["program"]]
        command_string = \
            check_info["interpreter_path"] \
            + " " + program_path \
            + " " + check_info["params"]
        try:
            output = subprocess.check_output(command_string, shell=True)
            returncode = 0
        except subprocess.CalledProcessError as result:
            output = result.output
            returncode = result.returncode
        return {"severity_code": returncode, "output": output.strip("\n")}

    def _save_program(self, program):
        logging.debug("Saving new program: "+ str(program["name"]))
        new_temp_file_handle = tempfile.mkstemp(dir=self._tmp_dir)
        self._program_file_names[program["name"]] = new_temp_file_handle[1]
        self._program_checksums[program["name"]] = self._get_checksum(program["code"] \
                                                      .replace("\r\n", "\n"))
        new_program_file = open(new_temp_file_handle[1], "w+")
        new_program_file.writelines(program["code"].replace("\r\n", "\n"))
        new_program_file.flush()
        new_program_file.close()
        logging.debug("Saved "+ str(program["name"]) +" as "+ str(new_temp_file_handle[1]))
        if program["name"] in self._pending_checks.keys():
            while not self._pending_checks[program["name"]].empty():
                pending_check = self._pending_checks[program["name"]].get()
                self._process_check(pending_check)

    def _get_checksum(self, text):
        return base64.urlsafe_b64encode(hashlib.sha256(text).digest())

    def _socket_send(self):
        self._socket_opened.wait()
        self._message_outbox_lock.acquire()
        while self.__running:
            try:
                message = self._message_outbox.get()
                message = self._add_auth_header(message)
                message = "\x02"+json.dumps(message)+"\x03"
            except:
                logging.exception("get and format message failed")
            try:
                self._socket.send(message)
            except socket.error:
                logging.exception("Socket error while send")
                self._socket_opened.clear()
                self._socket_closed.set()
            if self.__running:
                self._socket_opened.wait()
                self._message_outbox_lock.acquire()

    def _add_auth_header(self, message):
        serialized_message = json.dumps(message)
        hmac = self._get_hmac(serialized_message)
        return {"HMAC": hmac, "ID": self._username, "message": serialized_message}

    def _get_hmac(self, message):
        return hmac.new(self._hmac_secret, str(message), hashlib.sha256).hexdigest()

    def _connect_to_server(self):
        try:
            self._socket = socket.create_connection(self._server_socket_config, 5)
            self._socket.settimeout(2)
            if self._ssl_enabled:
                self._enable_ssl()
            return True
        except socket.error:
            logging.exception("Couldn't connect to server")
            return False
        except ssl.SSLError:
            logging.exception("Error connecting to server using ssl")
            return False

    def _enable_ssl(self):
        self._socket = self._ssl_context.wrap_socket(
            self._socket,
            server_hostname=self._ssl_fqdn,
            do_handshake_on_connect=False)
        while True:
            try:
                self._socket.do_handshake()
                break
            except ssl.SSLWantReadError:
                select.select([sock], [], [])
            except ssl.SSLWantWriteError:
                select.select([], [sock], [])


    def stop(self):
        self.__running = False
        self._socket_opened.set()
        self._socket_closed.set()
        self._message_inbox_lock.release()
        self._message_outbox_lock.release()
        self._socket_send_thread.join()
        self._socket_receive_thread.join()

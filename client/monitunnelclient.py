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


class MonitunnelClient(Thread):

    def __init__(self, username, hostname, hmac_secret, server_address, server_port=13337):
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
        self._socket_closed.clear()
        self._socket_opened.clear()
        self._message_inbox_lock = Semaphore(0)
        self._message_outbox_lock = Semaphore(0)
        self._program_file_names = {}
        self._tmp_dir = tempfile.mkdtemp()

    def run(self):
        self.__running = True
        self._socket_receive_thread.start()
        self._socket_send_thread.start()
        self._message_processing_thread.start()
        while self.__running:
            counter = 1
            while self.__running and not self.__connected:
                self.__connected = self._connect_to_server()
                time.sleep(2)
                logging.info("Wasn't able to connect to server. Try "+str(counter)+"...")
                counter += 1
            if self.__running:
                self._socket_opened.set()
                self._authenticate()
                self._socket_closed.wait()
                self.__connected = False

    def _authenticate(self):
        message = {"method": "auth", "body": self._hostname}
        self.send_message(message)

    def send_message(self, message):
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
            except socket.error as err:
                if err.message == "timed out":
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
            if message["message"]["method"] == "check":
                self._process_check(message["message"]["body"])
            elif message["message"]["method"] == "request_program":
                self._save_program(message["message"]["body"])
            self._message_inbox_lock.acquire()

    def _process_check(self, check_info):
        result = self._execute_check(check_info)
        if result:
            result["check"] = check_info
            result = {"method": "result", "body": result}
            self.send_message(result)

    def _execute_check(self, check_info):
        if self._program_is_available(check_info["program"]):
            return self.execute(check_info)
        else:
            self.send_message({"method": "request_program", "body": check_info["program"]})
            if check_info["program"] not in self._pending_checks.keys():
                self._pending_checks[check_info["program"]] = Queue()
            self._pending_checks[check_info["program"]].put(check_info)
            return False

    def _program_is_available(self, program_name):
        if program_name in self._program_file_names.keys():
            return True
        else:
            return False

    def execute(self, check_info):
        program_path = self._program_file_names[check_info["program"]]
        command_string = \
            check_info["interpreter_path"] \
            + " " + program_path \
            + " '" + check_info["params"] + "'"
        try:
            output = subprocess.check_output(command_string, shell=True)
            returncode = 0
        except subprocess.CalledProcessError as result:
            output = result.output
            returncode = result.returncode
        return {"severity_code": returncode, "output": output.strip("\n")}

    def _save_program(self, program):
        new_temp_file_handle = tempfile.mkstemp(dir=self._tmp_dir)
        self._program_file_names[program["name"]] = new_temp_file_handle[1]
        new_program_file = open(new_temp_file_handle[1], "w+")
        new_program_file.writelines(program["code"].replace("\r\n", "\n"))
        new_program_file.flush()
        new_program_file.close()
        if program["name"] in self._pending_checks.keys():
            while not self._pending_checks[program["name"]].empty():
                pending_check = self._pending_checks[program["name"]].get()
                self._process_check(pending_check)

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
            return True
        except socket.error:
            logging.exception("Couldn't connect to server")
            return False

    def stop(self):
        self.__running = False
        self._socket_opened.set()
        self._socket_closed.set()
        self._message_inbox_lock.release()
        self._message_outbox_lock.release()
        self._socket_send_thread.join()
        self._socket_receive_thread.join()

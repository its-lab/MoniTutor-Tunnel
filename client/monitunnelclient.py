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
        self._message_inbox = Queue()
        self._message_outbox = Queue()
        self._socket_opened = Event()
        self._socket_closed = Event()
        self._socket_closed.clear()
        self._socket_opened.clear()
        self._message_inbox_lock = Semaphore(0)
        self._message_outbox_lock = Semaphore(0)


    def run(self):
        self.__running = True
        self._socket_receive_thread.start()
        self._socket_send_thread.start()
        while self.__running:
            counter = 1
            while self.__running and not self.__connected:
                self.__connected = self._connect_to_server()
                time.sleep(2)
                logging.info("Wasn't able to connect to server. Try "+str(counter)+"...")
                counter+=1
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
        while self.__running:
            try:
                message = self._socket.recv(1024)
                if message == "":
                    raise socket.error("empty message")
                else:
                    self._message_inbox.put(message)
                    self._message_inbox_lock.release()
            except socket.error as err:
                if err.message == "timed out":
                    pass
                else:
                    logging.exception("socket error while receive")
                    self._socket_opened.clear()
                    self._socket_closed.set()
            if self.__running:
                self._socket_opened.wait()

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
        return hmac.new( self._hmac_secret, str(message), hashlib.sha256).hexdigest()

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



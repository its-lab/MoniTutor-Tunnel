import subprocess
import logging
from threading import Thread
from threading import Semaphore
from threading import Lock
import socket
from queue import Queue
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

    def run(self):
        self.__running = True
        while self.__running:
            counter = 1
            while not self.__connected:
                self.__connected = self._connect_to_server()
                time.sleep(2)
                logging.info("Wasn't able to connect to server. Try "+str(counter)+"...")
                counter+=1
            self._message_inbox_lock = Semaphore(0)
            self._message_outbox_lock = Semaphore(0)
            self._socket_receive_thread = Thread(target=self._socket_receive, name="receive")
            self._socket_send_thread = Thread(target=self._socket_send, name="send")
            self._socket_lock = Lock()
            self._socket_receive_thread.start()
            self._socket_send_thread.start()
            self._socket_lock.acquire()
            self.__connected = False
            self._message_inbox_lock.release()
            self._message_outbox_lock.release()
            self._socket_send_thread.join()
            self._socket_receive_thread.join()
            del self._socket_send_thread
            del self._socket_receive_thread


    def _socket_receive(self):
        while self.__connected:
            try:
                message = self._socket.recv(1024)
                if message == "":
                    raise socket.error("empty message")
                else:
                    self._message_inbox.put(message)
                    self._message_inbox_lock.release()
            except socket.error as err:
                if err.message == "timed out":
                    continue
                logging.exception("socket error while receive")
                self.__connected = False
                self._socket_lock.release()

    def _socket_send(self):
        self._message_outbox_lock.acquire()
        while self.__connected:
            message = self._message_outbox.get()
            message = self._add_auth_header(message)
            message = "\x02"+json.dumps(message)+"\x03"
            try:
                self._socket.send(message)
            except socket.error:
                logging.exception("Socket error while send")
                self.__connected = False
                self._socket_lock.release()

    def _add_auth_header(self, message):
        serialized_message = json.dumps(message)
        hmac = self._get_hmac(serialized_message)
        return {"HMAC": hmac, "ID": self._username, message: serialized_message}

    def _get_hmac(self, message):
        return hmac.new( self._hmac_secret, str(message), hashlib.sha256).hexdigest()

    def _connect_to_server(self):
        try:
            self._socket = socket.create_connection(self._server_socket_config)
            self._socket.settimeout(3)
            return True
        except socket.error:
            logging.exception("Couldn't connect to server")
            return False

    def stop(self):
        self.__running = False

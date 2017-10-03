import subprocess
import logging
from threading import Thread
import socket

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

    def run(self):
        self.__running = True
        while self.__running:
            while not self.__connected:
                self.__connected = self._connect_to_server()
            try:
                message = self._socket.recv(512)
                if message == "":
                    raise socket.error("empty message")
            except socket.error:
                logging.exception("socket error while receive")
                self.__connected = False
                del self._socket

    def _connect_to_server(self):
        try:
            self._socket = socket.create_connection(self._server_socket_config)
            return True
        except socket.error:
            logging.exception("Couldn't connect to server")
            return False

    def stop(self):
        self.__running = False

import socket
from threading import Thread


class MoniTunnelDaemon(Thread):

    def __init__(self, port=13337, address=""):
        super(MoniTunnelDaemon, self).__init__()
        self._config = {"port": port, "address": address}
        self.__running = False
        self.__socket_open = False

    def run(self):
        self.__running = True
        while self.__running:
            while not self.__socket_open and self.__running:
                try:
                    self._open_socket()
                    self.__socket_open = True
                except socket.error:
                    self.__socket_open = False
            try:
                client, client_address = self._socket.accept()
                client.sendall("Hello student")
                return True
            except socket.error as err:
                if err != "timed out":
                    self.__socket_open = False

    def _open_socket(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._config["address"], self._config["port"]))
        self._socket.listen(0)
        self._socket.settimeout(1)

    def stop(self):
        self.__running = False

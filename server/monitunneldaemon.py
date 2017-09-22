import socket
import time
from clientthread import ClientThread
from threading import Thread


class MoniTunnelDaemon(Thread):

    def __init__(self, port=13337, address=""):
        super(MoniTunnelDaemon, self).__init__()
        self._config = {"port": port, "address": address}
        self.__running = False
        self.__socket_open = False
        self.__thread_list = []

    def run(self):
        self.__running = True
        while self.__running:
            while not self.__socket_open and self.__running:
                self._open_socket()
            try:
                client_socket, client_address = self._socket.accept()
                self._start_new_client_thread(client_socket)
                self.__running = False
            except socket.error as err:
                if err.message != "timed out":
                    self.__socket_open = False
                    del self._socket
            except AttributeError:
                self.__running = False

    def _open_socket(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self._config["address"], self._config["port"]))
            self._socket.listen(0)
            self._socket.settimeout(1)
            self.__socket_open = True
        except socket.error as err:
            self.__socket_open = False
            time.sleep(1)

    def _start_new_client_thread(self, client_socket):
        client_thread = ClientThread(client_socket)
        client_thread.start()
        self.__thread_list.append(client_thread)

    def stop(self):
        self.__running = False
        for thread in self.__thread_list:
            thread.stop()
            thread.join()
        del self._socket

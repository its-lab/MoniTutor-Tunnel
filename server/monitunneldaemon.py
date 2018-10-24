import socket
import time
from clientthread import ClientThread
from threading import Thread
import ssl
import logging


class MoniTunnelDaemon(Thread):

    def __init__(self, port=13337,
                       address="",
                       db_host="",
                       db_port="",
                       db_engine="",
                       db_username="",
                       db_password="",
                       db_database="",
                       rabbit_host="127.0.0.1",
                       rabbit_task_exchange="task_exchange",
                       rabbit_result_exchange="result_exchange",
                       rabbit_username="guest",
                       rabbit_password="guest",
                       ssl_enabled=False,
                       ssl_cert="cert.pem",
                       ssl_key="key.pem"):
        super(MoniTunnelDaemon, self).__init__()
        self._config = {"port": port, "address": address}
        self.__running = False
        self.__socket_open = False
        self.__thread_list = []
        self.__db_config = {"host": db_host, "port": db_port,
                            "engine": db_engine, "username": db_username,
                            "password": db_password, "database": db_database}
        self.__rabbit_config = {"host": rabbit_host,
                                "task_exchange": rabbit_task_exchange,
                                "result_exchange": rabbit_result_exchange,
                                "username": rabbit_username,
                                "password": rabbit_password}
        self._ssl_enabled = ssl_enabled
        if ssl_enabled:
            self._ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            self._ssl_context.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)
        else:
            self._ssl_context = False

    def run(self):
        self.__running = True
        while self.__running:
            while not self.__socket_open and self.__running:
                logging.debug("Trying to open socket." + str(self._config))
                self._open_socket()
                logging.info("Server socket successfuly opened. "
                             + "Accepting connections on "
                             + str(self._config))
            try:
                client_socket, client_address = self._socket.accept()
                logging.info("New client: " + str(client_address))
                self._start_new_client_thread(client_socket, client_address[0])
            except socket.error as err:
                if err.message != "timed out":
                    logging.exception("Socket error. Restart socket.")
                    self.__socket_open = False
                    del self._socket
            except AttributeError:
                logging.exception("Attribute error. Client: "+ str(client_address))
                logging.critical("Stopping server due to critical exception")
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
            logging.exception("Socket error while trying to open new socket")
            self.__socket_open = False
            time.sleep(1)

    def _start_new_client_thread(self, client_socket, client_address):
        client_thread = ClientThread(client_socket, self.__db_config, self.__rabbit_config, self._ssl_enabled, self._ssl_context, client_address)
        logging.debug("Starting new client thread")
        client_thread.start()
        self.__thread_list.append(client_thread)

    def stop(self):
        logging.warn("Stop main thread.")
        self.__running = False
        for thread in self.__thread_list:
            logging.debug("Stop clientthread.")
            thread.stop()
            logging.debug("Wait for clientthread to join")
            thread.join()
        logging.info("All clientthreads joined. Delete main socket.")
        del self._socket

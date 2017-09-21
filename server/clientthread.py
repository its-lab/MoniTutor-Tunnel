from threading import Thread
from threading import Semaphore
from Queue import Queue
import socket


class ClientThread(Thread):

    def __init__(self, socket):
        super(ClientThread,self).__init__()
        self._socket = socket
        self._socket.settimeout(2)
        self.__message_inbox_lock = Semaphore(0)
        self.__message_inbox = Queue()
        self.__message_outbox_lock = Semaphore(0)
        self.__message_outbox = Queue()
        self.__thread_list = []
        self.__running = False


    def run(self):
        self.__running = True
        self.__start_socket_threads()
        while self.__running:
            try:
                self._send_message(self._receive_meassge())
            except socket.error as err:
                pass
    
    def _receive_meassge(self):
        self.__message_inbox_lock.acquire()
        while self.__running:
            return self.__message_inbox.get()
            self.__message_inbox_lock.acquire()

    def _send_message(self, message):
        self.__message_outbox.put(message)
        self.__message_outbox_lock.release()

    def stop(self):
        self.__running = False
        self.__message_outbox_lock.release()
        self.__message_inbox_lock.release()
        self.__stop_socket_threads()

    def __start_socket_threads(self):
        self.__thread_list.append(Thread(target=self.__socket_receive, name="socket_receive"))
        self.__thread_list.append(Thread(target=self.__socket_send, name="socket_receive"))
        for thread in self.__thread_list:
            thread.start()

    def __stop_socket_threads(self):
        for thread in self.__thread_list:
            thread.join()

    def __socket_receive(self):
        while self.__running:
            try:
                packet = self._socket.recv(1024)
                if packet == "":
                    raise socket.error
            except socket.error as err:
                self._socket.shutdown(socket.SHUT_RDWR)
                self.__running = False
                break
            self.__message_inbox.put(packet)
            self.__message_inbox_lock.release()

    def __socket_send(self):
        self.__message_outbox_lock.acquire()
        while self.__running:
            self._socket.send(self.__message_outbox.get())
            self.__message_outbox_lock.acquire()



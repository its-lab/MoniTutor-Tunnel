from threading import Thread
import json
from threading import Semaphore
from Queue import Queue
import db
from re import search
import socket


class ClientThread(Thread):

    def __init__(self, socket):
        super(ClientThread, self).__init__()
        self._socket = socket
        self.__message_inbox_lock = Semaphore(0)
        self.__message_inbox = Queue()
        self.__message_outbox_lock = Semaphore(0)
        self.__message_outbox = Queue()
        self.__thread_list = []
        self.__running = False

    def run(self):
        self.__running = True
        self._socket.settimeout(2)
        self.__start_socket_threads()
        while self.__running:
            try:
                message = self._get_next_message()
                if message and self._message_is_authorized(message):
                    reply_message = self._process_message(message)
                else:
                    reply_message = self._process_unauthorized_message(message)
                if message:
                    self._put_message_into_send_queue(reply_message)
            except socket.error as err:
                pass

    def _message_is_authorized(self, message):
        return False

    def _process_unauthorized_message(self, message):
        return message

    def _process_message(self, message):
        return message

    def _get_next_message(self):
        self.__message_inbox_lock.acquire()
        while self.__running:
            serialized_message = self.__message_inbox.get()
            return json.loads(serialized_message)
            self.__message_inbox_lock.acquire()
        return False

    def _put_message_into_send_queue(self, message):
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
        chunk_buffer = ""
        while self.__running:
            try:
                chunk = self._socket.recv(512)
                if chunk == "":
                    raise socket.error("empty packet")
            except socket.error as err:
                if err.message != "empty packet":
                    continue
                else:
                    self._socket.shutdown(socket.SHUT_RDWR)
                    self.__running = False
                    break
            messages, chunk_buffer = self._get_message_from_chunks(chunk, chunk_buffer)
            for message in messages:
                self.__message_inbox.put(message)
                self.__message_inbox_lock.release()

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

    def __socket_send(self):
        self.__message_outbox_lock.acquire()
        while self.__running:
            message = "\x02"+json.dumps(self.__message_outbox.get())+"\x03"
            self._socket.send(message)
            self.__message_outbox_lock.acquire()

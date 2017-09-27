from threading import Thread
import json
from threading import Semaphore
from Queue import Queue
from db import Db
from re import search
import socket
import hashlib
import hmac
import pika


class ClientThread(Thread):

    def __init__(self, socket, db_config="", rabbit_config=""):
        super(ClientThread, self).__init__()
        self._socket = socket
        self.__message_inbox_lock = Semaphore(0)
        self.__message_inbox = Queue()
        self.__message_outbox_lock = Semaphore(0)
        self.__message_outbox = Queue()
        self.__thread_list = []
        self.__username = None
        self.__hmac_secret = None
        self.__db_config = db_config
        self.__rabbit_config = rabbit_config
        self.__running = False
        self._connected_to_rabbit_mq = False
        self._connected_to_task_queue = False
        self._connected_to_result_queue = False

    def run(self):
        self.__running = True
        self._socket.settimeout(2)
        self.__start_message_processing_threads()

    def _message_is_authorized(self, message):
        if not self.__username:
            self.__username = message["ID"]
            self.__hmac_secret = self._get_hmac_secret(self.__username)
        message_hmac = hmac.new(str(self.__hmac_secret),
                                str(message["message"]),
                                hashlib.sha256).hexdigest()
        return message["HMAC"] == message_hmac

    def _get_hmac_secret(self, username):
        database_handle = self.__get_db_handle()
        hmac_secret = database_handle.query(Db.Auth_user) \
            .filter(Db.Auth_user.username == username) \
            .first() \
            .hmac_secret
        database_handle.close()
        return hmac_secret

    def __get_db_handle(self):
        db_engine_string = self.__db_config["engine"]+"://"
        if self.__db_config["username"] and self.__db_config["password"]:
            db_engine_string += self.__db_config["username"]+":"+self.__db_config["password"]
        if self.__db_config["host"]:
            db_engine_string += "@"+self.__db_config["host"]
        if self.__db_config["port"]:
            db_engine_string += ":"+self.__db_config["port"]
        if self.__db_config["database"]:
            db_engine_string += "/"+self.__db_config["database"]
        return Db(db_engine_string).Session()

    def _process_unauthorized_message(self, message):
        message["message"] = "Not authorized"
        self._put_message_into_send_queue(message)
        return True

    def _process_message(self, message):
        message = self._strip_authentication_header(message)
        try:
            if message["method"] == "echo" or message["method"] == "error":
                self._put_message_into_send_queue(message)
            elif message["method"] == "auth":
                self._identifier = self.__username+"."+str(message["body"])
                if not self._connected_to_task_queue:
                    self._connected_to_task_queue = True
                    self._task_queue_connection_thread = Thread(
                        target=self.__consume_tasks,
                        name="rabbit_consumer"
                        )
                    self._task_queue_connection_thread.start()
            elif message["method"] == "result":
                result = message["body"]
                result["hostname"] = self._identifier
                result["icingacmd_type"] = "PROCESS_SERVICE_CHECK_RESULT"
                self._publish_result(result)

        except TypeError as err:
            message = {
                       "method": "error",
                       "body": "message contains unexpected type",
                       "errorcode": 3}
            self._put_message_into_send_queue(message)
        return True

    def _publish_result(self, result):
        if not self._connected_to_result_queue:
            self._connect_to_result_queue()
        self._result_channel.basic_publish(
            exchange=self.__rabbit_config["result_exchange"],
            routing_key=self._identifier,
            body=json.dumps(result)
            )

    def __consume_tasks(self):
        while self.__running:
            self._connect_to_task_queue()
            try:
                self._rabbit_channel.start_consuming()
            except AttributeError:
                pass

    def _strip_authentication_header(self, message):
        try:
            serialized_message = message["message"]
            message = json.loads(serialized_message)
        except ValueError:
            message = {
                       "method": "error",
                       "body": "No JSON object could be decoded",
                       "errorcode": 1}
        except KeyError:
            message = {
                       "method": "error",
                       "body": "No message object could be found",
                       "errorcode": 2}
        except TypeError:
            message = {
                       "method": "error",
                       "body": "message contains unexpected type",
                       "errorcode": 3}
        return message

    def __process_inbox(self):
        self.__message_inbox_lock.acquire()
        while self.__running:
            serialized_message = self.__message_inbox.get()
            message = json.loads(serialized_message)
            if self._message_is_authorized(message):
                self._process_message(message)
            else:
                self._process_unauthorized_message(message)
                if self.__running:
                    self.__running = False
                    self.__wake_up_threads()
                break
            self.__message_inbox_lock.acquire()

    def _put_message_into_send_queue(self, message):
        self.__message_outbox.put(message)
        self.__message_outbox_lock.release()

    def stop(self):
        self.__running = False
        self.__message_outbox_lock.release()
        self.__message_inbox_lock.release()
        self.__stop_socket_threads()
        if self._connected_to_rabbit_mq:
            self._close_rabbit_connection()

    def __start_message_processing_threads(self):
        self.__thread_list.append(Thread(target=self.__socket_receive, name="socket_receive"))
        self.__thread_list.append(Thread(target=self.__socket_send, name="socket_receive"))
        self.__thread_list.append(Thread(target=self.__process_inbox, name="process_inbox"))
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
                    if self.__running:
                        self.__running = False
                        self.__wake_up_threads()
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
            message = "\x02"+json.dumps({"message": self.__message_outbox.get()})+"\x03"
            try:
                self._socket.send(message)
                self.__message_outbox_lock.acquire()
            except socket.error:
                if self.__running:
                    self.__running = False
                    self.__wake_up_threads()

    def _process_task(self, channel, method, properties, body_json):
        task = json.loads(body_json)
        message = {"method": "task", "body": task, "correlation_id": properties.correlation_id}
        self._put_message_into_send_queue(message)
        channel.basic_ack(delivery_tag=method.delivery_tag)

    def _connect_to_rabbit_mq(self):
            rabbit_connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=self.__rabbit_config["host"]))
            rabbit_connection.add_timeout(3, self._close_rabbit_connection)
            return rabbit_connection

    def _connect_to_task_queue(self):
        self._rabbit_connection = self._connect_to_rabbit_mq()
        self._rabbit_channel = self._rabbit_connection.channel()
        self._rabbit_channel.exchange_declare(
            exchange=self.__rabbit_config["task_exchange"],
            exchange_type="topic")
        self._task_queue = self._rabbit_channel.queue_declare(
            queue=self._identifier,
            durable=True)
        self._rabbit_channel.queue_bind(
            exchange=self.__rabbit_config["task_exchange"],
            queue=self._identifier,
            routing_key=self._identifier)
        self._rabbit_channel.basic_consume(
            self._process_task,
            queue=self._identifier)

    def _connect_to_result_queue(self):
        self._rabbit_result_connection = self._connect_to_rabbit_mq()
        self._result_channel = self._rabbit_result_connection.channel()
        self._result_channel.exchange_declare(
            exchange=self.__rabbit_config["result_exchange"],
            exchange_type="topic")
        self._connected_to_result_queue = True

    def _close_rabbit_connection(self):
        if self._connected_to_task_queue:
            self._rabbit_connection.close()
            self._connected_to_task_queue = False
        if self.__connected_to_result_queue:
            self._rabbit_result_connection.close()
            self.__connected_to_result_queue = False

    def __wake_up_threads(self):
        self.__message_inbox_lock.release()
        self.__message_outbox_lock.release()
        self._close_rabbit_connection()

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
import logging


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
        logging.debug("Clientthread started. Socket timeout set to 2 sec.")
        self.__start_message_processing_threads()

    def _message_is_authorized(self, message):
        if not self.__username:
            self.__username = message["ID"]
            logging.debug("Fetching hmac_secret of user "+message["ID"])
            self.__hmac_secret = self._get_hmac_secret(self.__username)
            logging.debug("hmac_secret of user "+message["ID"]+ " is "+self.__hmac_secret)
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
        self._put_message_into_send_queue(message)

    def _process_message(self, message):
        message = self._strip_authentication_header(message)
        try:
            if message["method"] == "echo" or message["method"] == "error":
                self._put_message_into_send_queue(message)
            elif message["method"] == "auth":
                self._identifier = self.__username+"."+str(message["body"])
                logging.debug("auth message received. Change identifier to"+str(self._identifier))
                if not self._connected_to_task_queue:
                    self._connected_to_task_queue = True
                    self._task_queue_connection_thread = Thread(
                        target=self.__consume_tasks,
                        name="rabbit_consumer")
                    logging.debug("Starting queue connection thread")
                    self._task_queue_connection_thread.start()
            elif message["method"] == "result":
                result = message["body"]
                result["hostname"] = self._identifier
                result["icingacmd_type"] = "PROCESS_SERVICE_CHECK_RESULT"
                self._publish_result(result)
            elif message["method"] == "request_program":
                code = self._get_program_code(message["body"])
                if code:
                    message["body"] = code
                else:
                    message = {
                       "method": "error",
                       "body": "program "+message["body"]+" unavailable",
                       "errorcode": 4}
                self._put_message_into_send_queue(message)

        except TypeError as err:
            message = {
                       "method": "error",
                       "body": "message contains unexpected type",
                       "errorcode": 3}
            logging.exception("Error while processing message")
            self._put_message_into_send_queue(message)
        return True

    def _get_program_code(self, program_name):
        try:
            database_handle = self.__get_db_handle()
            code = database_handle.query(Db.Programs) \
                .filter(Db.Programs.name == program_name) \
                .first().code
        except AttributeError:
           logging.exception("AttributeError while accessing Programs table")
           code = False
        finally:
            database_handle.close()
        return code

    def _publish_result(self, result):
        if not self._connected_to_result_queue:
            self._connect_to_result_queue()
        logging.debug("Publish result: "+str(result)+" to "+self._identifier)
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
            logging.exception("Error while stripping auth header")
        except KeyError:
            message = {
                       "method": "error",
                       "body": "No message object could be found",
                       "errorcode": 2}
            logging.exception("Error while stripping auth header")
        except TypeError:
            message = {
                       "method": "error",
                       "body": "message contains unexpected type",
                       "errorcode": 3}
            logging.exception("Error while stripping auth header")
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
                logging.debug("New chunk received: "+chunk)
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
            logging.debug("Received new messages: "+str(messages))
            logging.debug("Cunk_buffer from last chunk: "+str(chunk_buffer))
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
                logging.debug("sending: "+str(message))
                self._socket.send(message)
                self.__message_outbox_lock.acquire()
            except socket.error:
                logging.exception("socket error while sending. Stopping thread.")
                if self.__running:
                    self.__running = False
                    self.__wake_up_threads()

    def _process_task(self, channel, method, properties, body_json):
        logging.debug("Received new task from taskqueue: "+ str(body_json))
        task = json.loads(body_json)
        message = {"method": "task", "body": task, "correlation_id": properties.correlation_id}
        self._put_message_into_send_queue(message)
        channel.basic_ack(delivery_tag=method.delivery_tag)

    def _connect_to_rabbit_mq(self):
        logging.debug("Establishing new rabbit mq connection")
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
        logging.debug("Close rabbit mq connections")
        if self._connected_to_task_queue:
            self._rabbit_connection.close()
            self._connected_to_task_queue = False
        if self.__connected_to_result_queue:
            self._rabbit_result_connection.close()
            self.__connected_to_result_queue = False

    def __wake_up_threads(self):
        logging.debug("Wake up threads")
        self.__message_inbox_lock.release()
        self.__message_outbox_lock.release()
        self._close_rabbit_connection()

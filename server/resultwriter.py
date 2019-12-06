#!/usr/bin/python
import pika
from json import loads
from threading import Thread
import logging


class ResultWriter(Thread):

    def __init__(self, rabbit_host, result_exchange, task_exchange):
        Thread.__init__(self)
        self.__running = False
        self._config = {"rabbit_host": rabbit_host,
                        "result_exchange": result_exchange,
                        "task_exchange": task_exchange}

    def run(self):
        self.__running = True
        logging.info("Starting resultwrtier")
        while self.__running:
            self._connect_to_message_queue()
            try:
                self._rabbit_channel.start_consuming()
            except AttributeError:
                pass

    def stop(self):
        logging.info("Stopping Resultwriter")
        self.__running = False
        self.__rabbit_connection.close()

    def _connect_to_message_queue(self):
        logging.debug("connecting to rabbitMq")
        self.__rabbit_connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=self._config["rabbit_host"])
            )
        self._rabbit_channel = self.__rabbit_connection.channel()
        self._rabbit_channel.exchange_declare(
            exchange=self._config["result_exchange"],
            exchange_type="topic"
            )
        self.__result_queue = self._rabbit_channel.queue_declare("", exclusive=True)
        self._queue_name = self.__result_queue.method.queue
        self._rabbit_channel.queue_bind(
            exchange=self._config["result_exchange"],
            queue=self._queue_name,
            routing_key="#"
            )
        self._rabbit_channel.basic_consume(
            self._queue_name,
            self._message_callback,
            )

    def _message_callback(self, channel, method, properties, body_json):
        result = loads(body_json)
        logging.debug("Received message from rabbit: "+str(result))
        processed_result = self._process_result(result)
        self._write_result(processed_result)

    def _process_result(self, check_result):
        result_string = str(check_result)
        return result_string

    def _write_result(self, result):
        print(result)

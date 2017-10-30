#!/usr/bin/python
import subprocess
import pika
from json import loads
from threading import Thread


class ResultWriter(Thread):

    def __init__(self, rabbit_host, result_exchange, task_exchange,
                 icingacmd_path="/var/run/icinga2/cmd/icinga2.cmd"):
        Thread.__init__(self)
        self.__running = False
        self._config = {"rabbit_host": rabbit_host,
                        "result_exchange": result_exchange,
                        "task_exchange": task_exchange,
                        "icingacmd_path": icingacmd_path}

    def run(self):
        self.__running = True
        while self.__running:
            self._connect_to_message_queue()
            try:
                self._rabbit_channel.start_consuming()
            except AttributeError:
                pass

    def stop(self):
        self.__running = False
        self.__rabbit_connection.close()

    def _connect_to_message_queue(self):
        self.__rabbit_connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=self._config["rabbit_host"])
            )
        self._rabbit_channel = self.__rabbit_connection.channel()
        self._rabbit_channel.exchange_declare(
            exchange=self._config["result_exchange"],
            exchange_type="topic"
            )
        self.__result_queue = self._rabbit_channel.queue_declare(exclusive=True)
        self._queue_name = self.__result_queue.method.queue
        self._rabbit_channel.queue_bind(
            exchange=self._config["result_exchange"],
            queue=self._queue_name,
            routing_key="#"
            )
        self._rabbit_channel.basic_consume(
            self._message_callback,
            queue=self._queue_name,
            no_ack=True
            )

    def _message_callback(self, channel, method, properties, body_json):
        body = loads(body_json)
        icingacmd_string = self._get_icingacmd_string(body)
        icingacmd_commandline_string = self._get_icingacmd_commandline_string(icingacmd_string)
        self._execute_command(icingacmd_commandline_string)

    def _get_icingacmd_string(self, check_result):
        if check_result["icingacmd_type"] == "PROCESS_SERVICE_CHECK_RESULT":
            icingacmd_string = "[{0}] PROCESS_SERVICE_CHECK_RESULT;{1};{2};{3};{4}" \
                .format(check_result["time"],
                        check_result["hostname"],
                        check_result["name"],
                        check_result["severity_code"],
                        check_result["message"])
        else:
            icingacmd_string = "[{0}] PROCESS_HOST_CHECK_RESULT;{1};{2};{3}" \
                .format(check_result["time"],
                        check_result["hostname"],
                        check_result["severity_code"],
                        check_result["message"])
        return icingacmd_string

    def _get_icingacmd_commandline_string(self, icingacmd_string):
        return "echo '"+icingacmd_string+"' >> "+self._config["icingacmd_path"]+";"

    def _execute_command(self, command_string):
        try:
            output = subprocess.check_output(command_string, shell=True)
            returncode = 0
        except subprocess.CalledProcessError as result:
            output = result.output
            returncode = result.returncode
        finally:
            return {"output": output, "returncode": returncode}

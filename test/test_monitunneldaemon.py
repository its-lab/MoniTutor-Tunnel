import unittest
import time
import json
from mock import patch
import yaml
import socket
import hashlib
import hmac
from server.monitunneldaemon import MoniTunnelDaemon
from server.db import Db
import pika
import logging
import ssl


class MoniTunnelDaemonTestCase(unittest.TestCase):

    def setUp(self):
        config_file = open("./test/appconfig.yml")
        self.username = "admin"
        self.hostname = "itsclient"
        self.hmac_secret = "secret"
        app_config = yaml.load(config_file)
        self.config = {"port": app_config.get("monitunnel_port"),
                       "address": ""}
        self.config_rabbit = {"rabbit_host": app_config.get("rabbitmq_host"),
                              "result_exchange": app_config.get("result_exchange"),
                              "task_exchange": app_config.get("task_exchange")}
        self.monitunnelDaemon = MoniTunnelDaemon(
                port=self.config["port"],
                db_engine="sqlite",
                db_database="test.db",
                rabbit_task_exchange=self.config_rabbit["task_exchange"],
                rabbit_result_exchange=self.config_rabbit["result_exchange"],
                rabbit_host=self.config_rabbit["rabbit_host"])
        self.monitunnelDaemon.start()
        self.setUp_database()

    def setUp_database(self):
        self.database = Db("sqlite:///test.db")
        self.database.base.metadata.create_all(self.database.engine)
        session_handle = self.database.Session()
        if not session_handle.query(self.database.Auth_user).filter_by(username=self.username).first():
            session_handle.begin()
            session_handle.add(self.database.Auth_user(username=self.username, hmac_secret= self.hmac_secret))
            session_handle.commit()
        self.program = '''#!/bin/bash
if [[ "$1" == "test" ]]; then
    echo "OK"
    exit 0
else
    echo "ERROR"
    exit 1
fi
'''
        if not session_handle.query(self.database.Programs).filter_by(name="testcode").first():
            session_handle.begin()
            session_handle.add(self.database.Programs(name="testcode", display_name="Test Code", code=self.program))
            session_handle.commit()
        session_handle.flush()
        session_handle.close_all()
        del session_handle


    def test_connect_to_client_and_fetch_client_connected_result_from_queue(self):
        rabbitChannel, rabbitConnection = self.get_rabbit(self.config_rabbit["task_exchange"])
        result_queue = rabbitChannel.queue_declare(exclusive=True)
        rabbitChannel.queue_bind(
                exchange=self.config_rabbit["result_exchange"],
                queue = result_queue.method.queue,
                routing_key = self.username+"."+self.hostname)
        client = self._connect()
        message = {"method": "auth","body": self.hostname}
        hmac = self.get_hmac(json.dumps(message))
        packet = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        client.send(packet)
        time.sleep(1)
        get_ok, properties, result_from_queue = rabbitChannel.basic_get(result_queue.method.queue)
        self.assertNotEqual(result_from_queue, None, "Client connect result not send")
        del client
        time.sleep(7)
        get_ok, properties, result_from_queue = rabbitChannel.basic_get(result_queue.method.queue)
        self.assertNotEqual(result_from_queue, None, "Client disconnect result not send")

    def test_send_task_to_client_and_fetch_result_from_resultqueue(self):
        client = self._connect()
        message = {"method": "auth","body": self.hostname}
        hmac = self.get_hmac(json.dumps(message))
        packet = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        client.send(packet)
        task = {"program": "test_check.sh",
                "interpreter_path": "/bin/bash",
                "params": "/etc/hosts",
                "name": "test_check"}
        task_json = json.dumps(task)
        rabbitChannel, tabbitConnection = self.get_rabbit(self.config_rabbit["task_exchange"])
        rabbitChannel.basic_publish(
            exchange=self.config_rabbit["task_exchange"],
            routing_key=self.username+"."+self.hostname,
            properties=pika.BasicProperties(reply_to="asdf", content_type="application/json", correlation_id="1"),
            body=task_json)
        response = json.loads(client.recv(1024).strip("\x02\x03"))
        self.assertEqual(response["message"]["body"], task)
        self.assertEqual(response["message"]["correlation_id"], "1")
        rabbitChannel.close()
        time_now = int(time.time())
        result = {"time": str(time_now),
                  "severity_code": 1,
                  "output": "This is a test",
                  "name": task["name"],
                  "check": task,
                  "address": "127.0.0.1"
                 }
        message = {"method": "result","body": result}
        hmac = self.get_hmac(json.dumps(message))
        packet = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        rabbitChannel, rabbitConnection = self.get_rabbit(self.config_rabbit["result_exchange"])
        result_queue = rabbitChannel.queue_declare(exclusive=True)
        rabbitChannel.queue_bind(
                exchange=self.config_rabbit["result_exchange"],
                queue = result_queue.method.queue,
                routing_key = self.username+"."+self.hostname
                )
        client.send(packet)
        del client
        time.sleep(1)
        get_ok, properties, result_from_queue = rabbitChannel.basic_get(result_queue.method.queue)
        self.assertNotEqual(result_from_queue, None)
        result["type"] = "CHECK_RESULT"
        result["hostname"] = self.username +"_"+self.hostname
        self.assertEqual(dict(json.loads(result_from_queue)),dict(json.loads(json.dumps(result))))

    def test_send_task_with_attachment_to_client_and_fetch_result_from_resultqueue(self):
        client = self._connect()
        message = {"method": "auth","body": self.hostname}
        hmac = self.get_hmac(json.dumps(message))
        packet = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        client.send(packet)
        task = {"program": "test_check.sh",
                "interpreter_path": "/bin/bash",
                "params": "/etc/hosts",
                "name": "test_check",
                "attachments": [
                    {"producer": "/usr/bin/cat /etc/hosts",
                     "filter": "/usr/bin/grep 'asdf'",
                     "name": "test",
                     "requires_status": 1},
                    {"producer": "/usr/bin/cat /etc/hosts",
                     "name": "test2"},
                    ]
                }
        task_json = json.dumps(task)
        rabbitChannel, tabbitConnection = self.get_rabbit(self.config_rabbit["task_exchange"])
        rabbitChannel.basic_publish(
            exchange=self.config_rabbit["task_exchange"],
            routing_key=self.username+"."+self.hostname,
            properties=pika.BasicProperties(reply_to="asdf", content_type="application/json", correlation_id="1"),
            body=task_json)
        response = json.loads(client.recv(1024).strip("\x02\x03"))
        self.assertEqual(response["message"]["body"], task)
        self.assertEqual(response["message"]["correlation_id"], "1")
        rabbitChannel.close()
        time_now = int(time.time())
        result = {"time": str(time_now),
                  "severity_code": 1,
                  "output": "This is a test",
                  "name": task["name"],
                  "check": task,
                  "address": "127.0.0.1",
                  "attachments": [
                      {"name": "test",
                       "data": "asd"},
                      {"name": "test2",
                       "data": "asdf"}
                      ]
                 }
        message = {"method": "result","body": result}
        hmac = self.get_hmac(json.dumps(message))
        packet = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        rabbitChannel, rabbitConnection = self.get_rabbit(self.config_rabbit["result_exchange"])
        result_queue = rabbitChannel.queue_declare(exclusive=True)
        rabbitChannel.queue_bind(
                exchange=self.config_rabbit["result_exchange"],
                queue = result_queue.method.queue,
                routing_key = self.username+"."+self.hostname
                )
        rabbitChannel.queue_bind(
                exchange=self.config_rabbit["result_exchange"],
                queue = result_queue.method.queue,
                routing_key = "attachments."+self.username+"."+self.hostname
                )
        client.send(packet)
        time.sleep(1)
        result_messages = []
        get_ok, properties, result_from_queue = rabbitChannel.basic_get(result_queue.method.queue)
        result_messages.append(result_from_queue)
        get_ok, properties, result_from_queue = rabbitChannel.basic_get(result_queue.method.queue)
        result_messages.append(result_from_queue)
        result["hostname"] = self.username +"_"+self.hostname
        attachments_received = False
        del client
        for pos, result_from_queue in enumerate(result_messages):
            self.assertNotEqual(result_from_queue, None, "Message "+str(pos+1)+" missing")
            result_from_queue = json.loads(result_from_queue)
            if result_from_queue["type"] == "CHECK_RESULT":
                result_without_attachments = result.copy()
                result_without_attachments["type"] = "CHECK_RESULT"
                del result_without_attachments["attachments"]
                self.assertEqual(dict(result_from_queue),dict(json.loads(json.dumps(result_without_attachments))))
            elif result_from_queue["type"] == "ATTACHMENT":
                attachments_received = True
                result["type"] = "ATTACHMENT"
                self.assertEqual(dict(result_from_queue),dict(json.loads(json.dumps(result))))
        if not attachments_received:
            self.assertFail("ATTACHMENT message not received")

    def test_monitunnel_ip_config(self):
        self.assertEqual(self.config, self.monitunnelDaemon._config)

    @patch("server.clientthread.ClientThread._strip_authentication_header")
    @patch("server.clientthread.ClientThread._message_is_authorized")
    def test_daemon_newtork_socket(self, is_authorized, strip_header):
        # To only try the client server connection, we'll skip authentication
        is_authorized.return_value = True
        client = self._connect()
        echomsg = "hello world"
        message = {"message": {"method": "echo","body": echomsg }}
        # patch the auth header removal function to skip auth
        strip_header.return_value = message["message"]
        echopacket = "\x02"+json.dumps(message)+"\x03"
        client.send(echopacket+echopacket)
        time.sleep(.1)
        self.assertEqual(client.recv(1024), echopacket+echopacket)
        client.send(echopacket)
        self.assertEqual(client.recv(1024), echopacket)
        del client

    def test_request_program_code(self):
        client = self._connect()
        message = {"method": "request_program","body": "testcode"}
        hmac = self.get_hmac(json.dumps(message))
        packet = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        client.send(packet)
        serialized_program_message = client.recv(2048).strip("\x02\x03")
        del client
        program_message = json.loads(serialized_program_message)
        program_message = program_message["message"]
        self.assertEqual("request_program", program_message["method"])
        self.assertEqual(self.program, program_message["body"]["code"])
        self.assertEqual(message["body"], program_message["body"]["name"])

    def test_request_non_existent_program_code(self):
        client = self._connect()
        message = {"method": "request_program","body": "invalidtestcode"}
        hmac = self.get_hmac(json.dumps(message))
        packet = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        client.send(packet)
        serialized_program_message = client.recv(2048).strip("\x02\x03")
        del client
        program_message = json.loads(serialized_program_message)
        program_message = program_message["message"]
        self.assertEqual("error", program_message["method"])
        self.assertEqual(4, program_message["body"]["code"])

    @patch("server.clientthread.ClientThread._message_is_authorized")
    def test_client_message_format(self, is_authorized):
        # To only try the client server connection, we'll skip authentication
        is_authorized.return_value = True
        client = self._connect()
        message = {"method": "echo", "body": "This is a test message"}
        packet = "\x02"+json.dumps({"message": json.dumps(message), "HMAC": "empty", "ID": "test"})+"\x03"
        client.send(packet)
        time.sleep(.5)
        self.assertEqual(client.recv(1024).strip("\x02\x03"), json.dumps({"message": message}))
        error_packet = "\x02"+json.dumps({"message": "No Json", "HMAC": "empty", "ID": "test"})+"\x03"
        client.send(error_packet)
        time.sleep(.5)
        self.assertEqual(json.loads(client.recv(1024).strip("\x02\x03"))["message"]["body"]["code"], 1)
        error_packet = "\x02"+json.dumps({"mes": "No message key", "HMAC": "empty", "ID": "test"})+"\x03"
        client.send(error_packet)
        time.sleep(.5)
        self.assertEqual(json.loads(client.recv(1024).strip("\x02\x03"))["message"]["body"]["code"], 2)
        del client

    def test_client_authentication(self):
        client = self._connect()
        echomsg = "authenticated"
        message = {"method": "echo","body": echomsg}
        hmac = self.get_hmac(json.dumps(message))
        echopacket = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        client.send(echopacket)
        self.assertEqual(client.recv(1024).strip('\x02\x03"'), json.dumps({"message": message}))
        del client

    def test_ssl(self):
        self.monitunnelDaemon.stop()
        self.monitunnelDaemon.join()
        self.monitunnelDaemon = MoniTunnelDaemon(
                port=self.config["port"],
                db_engine="sqlite",
                db_database="test.db",
                rabbit_task_exchange=self.config_rabbit["task_exchange"],
                rabbit_result_exchange=self.config_rabbit["result_exchange"],
                rabbit_host=self.config_rabbit["rabbit_host"],
                ssl_enabled=True,
                ssl_key="key.pem",
                ssl_cert="cert.pem")
        self.monitunnelDaemon.start()
        context = ssl.create_default_context()
        context.load_verify_locations("cert.pem")
        client = self._connect()
        client = context.wrap_socket(client, server_hostname="example.com")
        echomsg = "authenticated"
        message = {"method": "echo","body": echomsg}
        hmac = self.get_hmac(json.dumps(message))
        echopacket = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        client.send(echopacket)
        self.assertEqual(client.recv(1024).strip('\x02\x03"'), json.dumps({"message": message}))
        del client


    def get_hmac(self, message):
        return hmac.new( self.hmac_secret, str(message), hashlib.sha256).hexdigest()

    def _connect(self):
        tries = 5
        connected = False
        while not connected and tries > 0:
            try:
                client = socket.create_connection(("127.0.0.1", self.config["port"]))
                connected = True
            except socket.error:
                logging.exception("Couldn't connect to server")
                tries -= 1
        if tries == 0:
            raise socket.error
        else:
            client.settimeout(2)
            return client

    def get_rabbit(self, exchange_name):
        rabbitConnection = pika.BlockingConnection(
            pika.ConnectionParameters(host=self.config_rabbit["rabbit_host"]))
        rabbitChannel = rabbitConnection.channel()
        rabbitChannel.exchange_declare(
            exchange=exchange_name,
            exchange_type='topic')
        return (rabbitChannel, rabbitConnection)


    def tearDown(self):
        self.monitunnelDaemon.stop()
        self.monitunnelDaemon.join()
        del self.database

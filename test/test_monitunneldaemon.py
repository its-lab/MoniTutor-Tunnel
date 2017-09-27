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
                rabbit_host=self.config_rabbit["rabbit_host"])
        self.monitunnelDaemon.start()
        self.database = Db("sqlite:///test.db")
        self.database.base.metadata.create_all(self.database.engine)
        session_handle = self.database.Session()
        if not session_handle.query(self.database.Auth_user).filter_by(username=self.username).first():
            session_handle.begin()
            session_handle.add(self.database.Auth_user(username=self.username, hmac_secret= self.hmac_secret))
            session_handle.commit()
        session_handle.flush()
        session_handle.close_all()
        del session_handle

    def test_send_task_to_client(self):
        client = self._connect()
        message = {"method": "auth","body": self.hostname}
        hmac = self.get_hmac(json.dumps(message))
        packet = "\x02"+json.dumps({"ID": self.username, "HMAC": hmac, "message": json.dumps(message)})+"\x03"
        client.send(packet)
        task = {"program": "test_check.sh",
                "interpreter_path": "/bin/bash",
                "params": "/etc/hosts"}
        task_json = json.dumps(task)
        rabbitConnection = pika.BlockingConnection(
            pika.ConnectionParameters(host=self.config_rabbit["rabbit_host"]))
        rabbitChannel = rabbitConnection.channel()
        rabbitChannel.exchange_declare(
            exchange=self.config_rabbit["task_exchange"],
            exchange_type='topic')
        rabbitChannel.basic_publish(
            exchange=self.config_rabbit["task_exchange"],
            routing_key=self.username+"."+self.hostname,
            properties=pika.BasicProperties(reply_to="asdf", content_type="application/json", correlation_id="1"),
            body=task_json)
        response = json.loads(client.recv(1024).strip("\x02\x03"))
        self.assertEqual(response["message"]["body"], task)
        self.assertEqual(response["message"]["correlation_id"], "1")
        del client

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
        self.assertEqual(json.loads(client.recv(1024).strip("\x02\x03"))["message"]["errorcode"], 1)
        error_packet = "\x02"+json.dumps({"mes": "No message key", "HMAC": "empty", "ID": "test"})+"\x03"
        client.send(error_packet)
        time.sleep(.5)
        self.assertEqual(json.loads(client.recv(1024).strip("\x02\x03"))["message"]["errorcode"], 2)
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
                tries -= 1
        if tries == 0:
            raise socket.error
        else:
            client.settimeout(2)
            return client

    def tearDown(self):
        self.monitunnelDaemon.stop()
        self.monitunnelDaemon.join()
        del self.database

import unittest
import time
import json
from mock import patch
import yaml
import socket
from server.monitunneldaemon import MoniTunnelDaemon
from server.db import Db


class MoniTunnelDaemonTestCase(unittest.TestCase):

    def setUp(self):
        config_file = open("./test/appconfig.yml")
        app_config = yaml.load(config_file)
        self.config = {"port": app_config.get("monitunnel_port"),
                       "address": ""}
        self.monitunnelDaemon = MoniTunnelDaemon(port=self.config["port"])
        self.monitunnelDaemon.start()
        self.database = Db("sqlite://")
        self.database.base.metadata.create_all(self.database.engine)
        session_handle = self.database.Session()
        if not session_handle.query(self.database.Auth_user).filter_by(username="admin").first():
            session_handle.add(self.database.Auth_user(username="admin", hmac_secret="secret"))

    def test_monitunnel_ip_config(self):
        self.assertEqual(self.config, self.monitunnelDaemon._config)

    @patch("server.clientthread.ClientThread._process_message")
    @patch("server.clientthread.ClientThread._message_is_authorized")
    def test_daemon_newtork_socket(self, is_authorized, process_message):
        # To only try the client server connection, we'll skip authentication
        is_authorized.return_value = True
        tries = 3
        connected = False
        while not connected and tries > 0:
            try:
                client = socket.create_connection(("127.0.0.1", self.config["port"]))
                connected = True
            except socket.error:
                tries -= 1
        echomsg = "hello world"
        echopacket = "\x02"+json.dumps({"body": echomsg })+"\x03"
        # patch the message processing, so that the server echos our request
        process_message.return_value = echomsg
        client.settimeout(2)
        client.send(echopacket+echopacket)
        time.sleep(.5)
        self.assertEqual(client.recv(1024), echomsg+echomsg)
        client.send(echopacket)
        self.assertEqual(client.recv(1024), echomsg)

    def tearDown(self):
        self.monitunnelDaemon.stop()

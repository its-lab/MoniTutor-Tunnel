import unittest
import json
from mock import patch
import yaml
import socket
from server.monitunneldaemon import MoniTunnelDaemon
import test.db as db


class MoniTunnelDaemonTestCase(unittest.TestCase):

    def setUp(self):
        config_file = open("./test/appconfig.yml")
        app_config = yaml.load(config_file)
        self.config = {"port": app_config.get("monitunnel_port"),
                       "address": ""}
        self.monitunnelDaemon = MoniTunnelDaemon(port=self.config["port"])
        self.monitunnelDaemon.start()
        session = db.Session()
        db.Base.metadata.create_all(db.engine)
        if not session.query(db.Auth_user).filter_by(username="admin").first():
            session.add(db.Auth_user(username="admin", hmac_secret="secret"))

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
        self.assertEqual(client.recv(1024), echomsg)
        self.assertEqual(client.recv(1024), echomsg)
        client.send(echopacket)
        self.assertEqual(client.recv(1024), echomsg)

    def tearDown(self):
        self.monitunnelDaemon.stop()

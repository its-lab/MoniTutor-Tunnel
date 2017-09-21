import time
import unittest
import yaml
import socket
from server.monitunneldaemon import MoniTunnelDaemon

class MoniTunnelDaemonTestCase(unittest.TestCase):

    def setUp(self):
        config_file = open("./test/appconfig.yml")
        app_config = yaml.load(config_file)
        self.config = {"port": app_config.get("monitunnel_port"),
                       "address": ""}
        self.monitunnelDaemon = MoniTunnelDaemon(port=self.config["port"])
        self.monitunnelDaemon.start()

    def test_monitunnel_ip_config(self):
        self.assertEqual(self.config, self.monitunnelDaemon._config)

    def test_daemon_newtork_socket(self):
        tries = 3
        connected = False
        while not connected and tries > 0:
            try:
                client = socket.create_connection(("127.0.0.1", self.config["port"]))
                connected = True
            except socket.error:
                tries -= 1
        echomsg = "hello world"
        client.settimeout(2)
        client.send(echomsg)
        self.assertEqual(client.recv(1024), echomsg)
        echomsg = "hello world 2"
        client.send(echomsg)
        self.assertEqual(client.recv(1024), echomsg)

    def tearDown(self):
        self.monitunnelDaemon.stop()

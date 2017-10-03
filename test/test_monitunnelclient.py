from client.monitunnelclient import MonitunnelClient
import socket
import time
import unittest


class MonitunnelClientTestCase(unittest.TestCase):

    def setUp(self):
        self._username = "testuser"
        self._hostname = "testhost"
        self._hmac_secret = "secure_hmac_secret"
        self._server_address = "127.0.0.1"
        self._server_port = 12345
        self.client = MonitunnelClient(
                self._username,
                self._hostname,
                self._hmac_secret,
                self._server_address,
                self._server_port)

    def test_monitunnel_init(self):
        self.assertEqual(self.client._username, self._username)
        self.assertEqual(self.client._hostname, self._hostname)
        self.assertEqual(self.client._hmac_secret, self._hmac_secret)
        self.assertEqual(self.client._server_socket_config,(self._server_address, self._server_port))

    def test_monitunnel_connect_and_reconnect(self):
        self.client.start()
        self.assertIs( tuple , type(self._start_server_and_return_clientsocket()))
        del self._server_socket
        self.assertIs( tuple , type(self._start_server_and_return_clientsocket()), "Reconnect failed")
        del self._server_socket
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.shutdown(socket.SHUT_RDWR)
        del self._server_socket
        self.assertIs( tuple , type(self._start_server_and_return_clientsocket()), "Hard reset and reconnect failed")

    def test_message_authentication(self):
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(1)
        try:
            message = client_socket.recv(1024)
        except:
            del client_socket
        del self._server_socket

    def tearDown(self):
        if self.client._MonitunnelClient__running:
            self.client.stop()
            self.client.join()

    def _start_server_and_return_clientsocket(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self._server_address, int(self._server_port)))
        self._server_socket.listen(0)
        self._server_socket.settimeout(3)
        return self._server_socket.accept()

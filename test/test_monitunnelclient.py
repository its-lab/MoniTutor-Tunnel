from client.monitunnelclient import MonitunnelClient
import socket
import time
import unittest
import json
from mock import patch
from os import remove
from os import path


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
        del self._server_socket

    def test_message_authentication(self):
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(3)
        try:
            message = client_socket.recv(1024)
        except socket.error:
            del self._server_socket
            raise socket.error
        else:
            pass
        self.assertIn("\x02", message, "Startstring control char missing")
        self.assertIn("\x03", message, "Endofstring control char missing")
        message = message.strip("\x02\x03")
        message = json.loads(message)
        self.assertIn( "HMAC", message.keys())
        self.assertIn( "ID", message.keys())
        self.assertIn( "message", message.keys())
        del self._server_socket

    @patch("client.monitunnelclient.MonitunnelClient._execute_check")
    def test_message_check(self, execute_check):
        execute_check.return_value = {"output": "OK", "severity_code": 0}
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(3)
        try:
            client_socket.recv(1024)
        except socket.error:
            del self._server_socket
            raise socket.error
        message = {"message":
                    {"method": "check",
                     "body":
                       {"program": "test.sh",
                        "interpreter_path": "/bn/bash",
                        "params": "/etc/hosts",
                        "id": 1,
                        "name": "test /etc/hosts"
                       }
                     }
                   }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
        time.sleep(2)
        response = client_socket.recv(1024)
        response = response.strip("\x02\x03")
        result = json.loads(response)
        result = json.loads(result["message"])
        self.assertEquals(str(result["method"]), "result")
        self.assertEquals(result["body"]["severity_code"], 0)
        self.assertEquals(str(result["body"]["output"]), "OK")
        self.assertIn("check", result["body"])
        self.assertEquals(message["message"]["body"], result["body"]["check"])
        del self._server_socket

    @patch("client.monitunnelclient.MonitunnelClient._program_is_available")
    def test_check_execution(self, program_is_available):
        program_is_available.return_value = False
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(3)
        try:
            client_socket.recv(1024)
        except socket.error:
            del self._server_socket
            raise socket.error
        message = {"message":
                    {"method": "check",
                     "body":
                       {"program": "test.sh",
                        "interpreter_path": "/bn/bash",
                        "params": "/etc/hosts",
                        "id": 1,
                        "name": "test /etc/hosts"
                       }
                     }
                   }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
        time.sleep(2)
        response = client_socket.recv(1024)
        response = response.strip("\x02\x03")
        result = json.loads(response)
        result = json.loads(result["message"])
        self.assertEqual("request_program", result["method"])
        self.assertEqual("test.sh", result["body"])
        del self._server_socket

    @patch("client.monitunnelclient.MonitunnelClient.execute")
    def test_program_request_answer(self, execute_check):
        execute_check.return_value = {"output": "OK", "severity_code": 0}
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(3)
        try:
            client_socket.recv(1024)
        except socket.error:
            del self._server_socket
            raise socker.error
        message = {"message":
                    {"method": "request_program",
                     "body": {
                       "name": "test.sh",
                       "code": '''#!/bin/bash
if [[ -f $1 ]]; then
  echo "OK"
  exit 0
else
  echo "$1 not found"
  exit 2
fi
'''}
                     }
                   }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
        time.sleep(1)
        message = {"message":
                    {"method": "check",
                     "body":
                       {"program": "test.sh",
                        "interpreter_path": "/bn/bash",
                        "params": "/etc/hosts",
                        "id": 1,
                        "name": "test_/etc/hosts"
                       }
                     }
                   }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
        time.sleep(1)
        response = client_socket.recv(1024)
        response = response.strip("\x02\x03")
        result = json.loads(response)
        result = json.loads(result["message"])
        self.assertEquals(str(result["method"]), "result")
        self.assertEquals(result["body"]["severity_code"], 0)
        self.assertEquals(str(result["body"]["output"]), "OK")
        self.assertIn("check", result["body"])
        self.assertEquals(message["message"]["body"], result["body"]["check"])
        del self._server_socket

    def test_execute(self):
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(3)
        client_socket.recv(1024)
        test_program_code = '''#!/bin/bash
if [[ -f $1 ]]; then
  echo "OK"
  exit 0
else
  echo "$1 not found"
  exit 2
fi'''
        with open("./test/test.sh", "w+") as test_prog_file:
            test_prog_file.writelines(test_program_code)
            test_prog_file.flush()
        self.client._program_file_names["test.sh"] = path.abspath("./test/test.sh")
        message = {"message":
                    {"method": "check",
                     "body":
                       {"program": "test.sh",
                        "interpreter_path": "/bin/bash",
                        "params": "/etc/hosts",
                        "id": 1,
                        "name": "test_/etc/hosts"
                       }
                     }
                   }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
        time.sleep(1)
        response = client_socket.recv(1024)
        response = response.strip("\x02\x03")
        result = json.loads(response)
        result = json.loads(result["message"])
        self.assertEquals(str(result["method"]), "result")
        self.assertEquals(result["body"]["severity_code"], 0)
        self.assertEquals(str(result["body"]["output"]), "OK")
        self.assertIn("check", result["body"])
        self.assertEquals(message["message"]["body"], result["body"]["check"])
        remove("./test/test.sh")
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
        self._server_socket.settimeout(4)
        return self._server_socket.accept()

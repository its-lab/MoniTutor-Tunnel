from client.monitunnelclient import MonitunnelClient
import socket
import time
import unittest
import json
from mock import patch
from os import remove
from os import path
import ssl
from base64 import b64encode
from base64 import b64decode


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
        self._server_running = False

    def test_monitunnel_init(self):
        self.assertEqual(self.client._username, self._username)
        self.assertEqual(self.client._hostname, self._hostname)
        self.assertEqual(self.client._hmac_secret, self._hmac_secret)
        self.assertEqual(self.client._server_socket_config,
                         (self._server_address, self._server_port))

    def test_monitunnel_connect_and_reconnect(self):
        self.client.start()
        self.assertIs(tuple, type(self._start_server_and_return_clientsocket()))
        del self._server_socket
        self.assertIs(tuple, type(self._start_server_and_return_clientsocket()),
                      "Reconnect failed")
        del self._server_socket
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.shutdown(socket.SHUT_RDWR)
        del self._server_socket
        self.assertIs(tuple, type(self._start_server_and_return_clientsocket()),
                      "Hard reset and reconnect failed")

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
        self.assertIn("HMAC", message.keys())
        self.assertIn("ID", message.keys())
        self.assertIn("message", message.keys())

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
        message = {
            "message":
            {
                "method": "task",
                "body":
                {
                    "program": "test.sh",
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
        message = {
            "message":
            {
                "method": "task",
                "body":
                {
                    "program": "test.sh",
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
            raise socket.error
        message = {
            "message":
            {
                "method": "request_program",
                "body": {
                    "name": "test.sh",
                    "code": test_program_code
                    }
                }
            }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
        time.sleep(1)
        message = {
            "message":
            {
                "method": "task",
                "body":
                {
                    "program": "test.sh",
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

    @patch("client.monitunnelclient.MonitunnelClient._program_is_available")
    def test_execute(self, program_is_available):
        program_is_available.return_value = True
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(4)
        client_socket.recv(1024)
        with open("./test/test.sh", "w+") as test_prog_file:
            test_prog_file.writelines(test_program_code)
            test_prog_file.flush()
        self.client._program_file_names["test.sh"] = path.abspath("./test/test.sh")
        message = {
            "message":
            {
                "method": "task",
                "body":
                {
                    "program": "test.sh",
                    "interpreter_path": "/bin/bash",
                    "params": "/etc/hosts",
                    "id": 1,
                    "name": "test_/etc/hosts"
                    }
                }
            }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
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

    @patch("client.monitunnelclient.MonitunnelClient._program_is_available")
    def test_execute_check_with_attachment(self, program_is_available):
        program_is_available.return_value = True
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(4)
        client_socket.recv(1024)
        with open("./test/test.sh", "w+") as test_prog_file:
            test_prog_file.writelines(test_program_code)
            test_prog_file.flush()
        self.client._program_file_names["test.sh"] = path.abspath("./test/test.sh")
        attachments = [
                        {
                            "producer": "/usr/bin/cat ./test/test.sh",
                            "filter": "/usr/bin/tail",
                            "name": "test_program_tail"
                            },
                        {
                            "producer": "/usr/bin/cat ./test/test.sh",
                            "filter": "/usr/bin/grep 'fi'",
                            "name": "test_program_grep"
                            },
                        {
                            "producer": "/usr/bin/cat ./test/test.sh",
                            "name": "test_program"
                            },
                        {
                            "producer": "/usr/bin/cat ./test/test.sh",
                            "name": "test_program_1",
                            "requires_status": 1
                            },
                        {
                            "producer": "/usr/bin/cat ./test/test.sh",
                            "name": "test_program_0",
                            "requires_status": 0
                            }
                        ]
        message = {
            "message":
            {
                "method": "task",
                "body":
                {
                    "program": "test.sh",
                    "interpreter_path": "/bin/bash",
                    "params": "/etc/hosts",
                    "id": 1,
                    "name": "test_/etc/hosts",
                    "attachments": attachments
                    }
                }
            }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
        response = client_socket.recv(1024)
        responses = []
        while "\x03" not in response:
            responses.append(response)
            response = client_socket.recv(1024)
        responses.append(response)
        response = "".join(responses)
        response = response.strip("\x02\x03")
        result = json.loads(response)
        result = json.loads(result["message"])
        self.assertEquals(result["body"]["severity_code"], 0)
        self.assertEquals(str(result["body"]["output"]), "OK")
        remove("./test/test.sh")
        self.assertIn("attachments", result["body"], "Body doesn't contain attachments")
        result_attachments = result["body"]["attachments"]
        print result_attachments
        for attachment in attachments:
            attachment_received = False
            for result_attachment in result_attachments:
                print result_attachment["name"]
                if result_attachment["name"] == attachment["name"]:
                    attachment_received = True
                    name = attachment["name"]
                    data = b64decode(result_attachment["data"])
                    if name in ["test_program", "test_program_tail", "test_program_0"]:
                        self.assertEqual(test_program_code, data)
                    elif name == "test_program_grep":
                        self.assertEqual("fi\n", data)
                        print "asd"
                    elif name == "test_program_1":
                        self.fail("test_program_1 was executed")
            if not attachment_received:
                if attachment["name"] != "test_program_1":
                    self.fail("Missing attachment: "+attachment["name"])

    def test_execute_check_after_program_was_requested(self):
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(3)
        client_socket.recv(1024)
        with open("./test/test.sh", "w+") as test_prog_file:
            test_prog_file.writelines(test_program_code)
            test_prog_file.flush()
        message = {
            "message":
            {
                "method": "task",
                "body":
                {
                    "program": "test.sh",
                    "interpreter_path": "/bin/bash",
                    "params": "/etc/hosts",
                    "id": 1,
                    "name": "test_/etc/hosts"
                    }
                }
            }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
        response = client_socket.recv(1024)
        response = response.strip("\x02\x03")
        result = json.loads(response)
        result = json.loads(result["message"])
        self.assertEquals(str(result["method"]), "request_program")
        self.assertEquals(result["body"], message["message"]["body"]["program"])
        code_message = {
            "message":
            {
                "method": "request_program",
                "body": {
                    "name": "test.sh",
                    "code": test_program_code
                    }
                }
            }
        client_socket.send("\x02"+json.dumps(code_message)+"\x03")
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

    def test_execute_check_after_program_was_altered(self):
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket.settimeout(3)
        client_socket.recv(1024)
        code_message = {
            "message":
            {
                "method": "request_program",
                "body": {
                    "name": "test.sh",
                    "code": test_program_code
                    }
                }
            }
        client_socket.send("\x02"+json.dumps(code_message)+"\x03")
        time.sleep(1)
        filename = self.client._program_file_names["test.sh"]
        with open(filename, "a") as checkfile:
            checkfile.write("Test\n")
            checkfile.flush()
        message = {
            "message":
            {
                "method": "task",
                "body":
                {
                    "program": "test.sh",
                    "interpreter_path": "/bin/bash",
                    "params": "/etc/hosts",
                    "id": 1,
                    "name": "test_/etc/hosts"
                    }
                }
            }
        client_socket.send("\x02"+json.dumps(message)+"\x03")
        response = client_socket.recv(1024)
        response = response.strip("\x02\x03")
        result = json.loads(response)
        result = json.loads(result["message"])
        self.assertEquals(str(result["method"]), "request_program")
        self.assertEquals(result["body"], message["message"]["body"]["program"])

    def test_ssl(self):
        self.client = MonitunnelClient(
                self._username,
                self._hostname,
                self._hmac_secret,
                self._server_address,
                self._server_port,
                ssl_enabled=True,
                ssl_cert="cert.pem")
        context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        self.client.start()
        client_socket, address = self._start_server_and_return_clientsocket()
        client_socket = context.wrap_socket(client_socket, server_side=True, do_handshake_on_connect=False)
        while True:
            try:
                client_socket.do_handshake()
                break
            except ssl.SSLWantReadError:
                select.select([sock], [], [])
            except ssl.SSLWantWriteError:
                select.select([], [sock], [])
        try:
            message = client_socket.recv(1024).strip("\x03\x02")
        except socket.error:
            del self._server_socket
            raise socket.error
        else:
            pass
        message = json.loads(message)
        self.assertIn("message", message.keys())


    def tearDown(self):
        if self._server_running:
            del self._server_socket
            self._server_running = False
        if self.client._MonitunnelClient__running:
            self.client.stop()
            self.client.join()

    def _start_server_and_return_clientsocket(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self._server_address, int(self._server_port)))
        self._server_socket.listen(0)
        self._server_socket.settimeout(4)
        self._server_running = True
        return self._server_socket.accept()


test_program_code = '''#!/bin/bash
if [[ -f $1 ]]; then
  echo "OK"
  exit 0
else
  echo "$1 not found"
  exit 2
fi'''

import unittest
import os
import yaml
from server.resultwriter import ResultWriter
import time
import pika
import json

class ResultwriterTestCase(unittest.TestCase):

    def setUp(self):
        config_file = open("./test/appconfig.yml")
        app_config = yaml.load(config_file)
        self.config = {"rabbit_host": app_config.get("rabbitmq_host"),
                       "result_exchange": app_config.get("result_exchange"),
                       "task_exchange": app_config.get("task_exchange"),
                       "icingacmd_path": "./test/icingacmd.log"}
        self.resultwriter = ResultWriter(rabbit_host=self.config["rabbit_host"],
                                    result_exchange=self.config["result_exchange"],
                                    task_exchange=self.config["task_exchange"],
                                    icingacmd_path=self.config["icingacmd_path"])
        self.rabbitConnection = pika.BlockingConnection(
            pika.ConnectionParameters(host=self.config["rabbit_host"])
            )
        self.rabbitChannel = self.rabbitConnection.channel()
        self.rabbitChannel.exchange_declare(
                exchange=self.config["result_exchange"],
                exchange_type='topic')

    def tearDown(self):
        try:
            self.resultwriter.stop()
            self.resultwriter.join()
        except:
            pass

    def test_set_rabbitmq_config(self):
        self.assertEqual(self.resultwriter._config,
                         self.config, "Setting rabbitMQ config failed" )

    def test_icingacmd_string_formatter(self):
        time_now = int(time.time())
        check_result = {"icingacmd_type": "PROCESS_SERVICE_CHECK_RESULT",
                        "time": str(time_now),
                        "name": "administrator_ping_myself",
                        "hostname": "administrator_itsclient",
                        "severity_code": 1,
                        "message": "OK - All fine"}
        resultstring = "["+str(time_now)+"] PROCESS_SERVICE_CHECK_RESULT;administrator_itsclient;administrator_ping_myself;1;OK - All fine"
        self.resultwriter._get_icingacmd_string(check_result)
        self.assertEqual(self.resultwriter._get_icingacmd_string(check_result),
                         resultstring,
                         "Service check result string not properly formatted")
        check_result["icingacmd_type"] = "PROCESS_HOST_CHECK_RESULT"
        check_result["message"] = "Not Connected"
        resultstring = "["+str(time_now)+"] PROCESS_HOST_CHECK_RESULT;administrator_itsclient;1;Not Connected"
        self.assertEqual(self.resultwriter._get_icingacmd_string(check_result), resultstring,
                         "Host check result string not properly formatted")

    def test_icingacmd_command_formatter(self):
        self.assertEqual(self.resultwriter._get_icingacmd_commandline_string("<ICINGACMD_STRING>"),
                         "echo '<ICINGACMD_STRING>' >> "+self.resultwriter._config["icingacmd_path"]+";")

    def test_command_execution(self):
        self.assertTrue(0==self.resultwriter._execute_command("exit 0")["returncode"])
        self.assertTrue(1==self.resultwriter._execute_command("exit 1")["returncode"])
        self.assertEquals("test\n", self.resultwriter._execute_command("echo 'test'")["output"])
        self.assertEquals({"output":"test2\n", "returncode": 0},
                          self.resultwriter._execute_command("echo 'test2'"))
        self.assertEquals({"output":"test3\n", "returncode": 1},
                          self.resultwriter._execute_command("echo 'test3'; exit 1"))

    def test_callback_function(self):
        time_now = str(int(time.time()))
        result = {"icingacmd_type": "PROCESS_SERVICE_CHECK_RESULT",
                  "time": time_now,
                  "name": "administrator_ping_myself",
                  "hostname": "administrator_itsclient",
                  "severity_code": 1,
                  "message": "OK - All fine"}
        resultstring = "["+str(time_now)+"] PROCESS_SERVICE_CHECK_RESULT;administrator_itsclient;administrator_ping_myself;1;OK - All fine"
        if os.access(self.config["icingacmd_path"], os.R_OK):
            os.remove(self.config["icingacmd_path"])
        self.resultwriter._message_callback(" ", " ", " ", json.dumps(result))
        time.sleep(.3)
        self.assertEqual(resultstring,
                         open(self.config["icingacmd_path"]).readline().rstrip())
        os.remove(self.config["icingacmd_path"])
        del result["name"]
        result["icingacmd_type"] = "PROCESS_HOST_CHECK_RESULT"
        resultstring = "["+str(time_now)+"] PROCESS_HOST_CHECK_RESULT;administrator_itsclient;1;OK - All fine"
        self.resultwriter._message_callback(" ", " ", " ", json.dumps(result))
        time.sleep(.3)
        self.assertEqual(resultstring,
                         open(self.config["icingacmd_path"]).readline().rstrip())
        os.remove(self.config["icingacmd_path"])

    def test_pika_consumer(self):
        self.resultwriter.start()
        time.sleep(.5)
        time_now = str(int(time.time()))
        result = {"icingacmd_type": "PROCESS_SERVICE_CHECK_RESULT",
                  "time": time_now,
                  "name": "administrator_ping_myself",
                  "hostname": "administrator_itsclient",
                  "severity_code": 1,
                  "message": "OK - All fine"}
        result_json = json.dumps(result)
        self.rabbitChannel.basic_publish(
                exchange=self.config["result_exchange"],
                routing_key="service.test",
                body=result_json)
        resultstring = "["+str(time_now)+"] PROCESS_SERVICE_CHECK_RESULT;administrator_itsclient;administrator_ping_myself;1;OK - All fine"
        time.sleep(.5)
        self.assertEqual(resultstring,
                         open(self.config["icingacmd_path"]).readline().rstrip())
        os.remove(self.config["icingacmd_path"])
        del result["name"]
        result["icingacmd_type"] = "PROCESS_HOST_CHECK_RESULT"
        resultstring = "["+str(time_now)+"] PROCESS_HOST_CHECK_RESULT;administrator_itsclient;1;OK - All fine"
        result_json = json.dumps(result)
        self.rabbitChannel.basic_publish(
                exchange=self.config["result_exchange"],
                routing_key="service.test",
                body=result_json)
        time.sleep(.5)
        self.assertEqual(resultstring,
                         open(self.config["icingacmd_path"]).readline().rstrip())
        os.remove(self.config["icingacmd_path"])


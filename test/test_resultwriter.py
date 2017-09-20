import unittest
import yaml
from server.resultwriter import ResultWriter
import time

class ResultwriterTestCase(unittest.TestCase):

    def setUp(self):
        config_file = open("./test/appconfig.yml")
        app_config = yaml.load(config_file)
        self.config = {"rabbit_host": app_config.get("rabbit_host"),
                       "result_exchange": app_config.get("result_exchange"),
                       "task_exchange": app_config.get("task_exchange"),
                       "icingacmd_path": "./icingacmd"}
        self.resultwriter = ResultWriter(rabbit_host=self.config["rabbit_host"],
                                    result_exchange=self.config["result_exchange"],
                                    task_exchange=self.config["task_exchange"],
                                    icingacmd_path=self.config["icingacmd_path"])

    def test_set_rabbitmq_config(self):
        self.assertEqual(self.resultwriter._config,
                         self.config, "Setting rabbitMQ config failed" )

    def test_icingacmd_string_formatter(self):
        time_now = int(time.time())
        check_result = {"icingacmd_type": "PROCESS_SERVICE_CHECK_RESULT",
                        "time": str(time_now),
                        "name": "administrator_ping_myself",
                        "host": "administrator_itsclient",
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
        result = self.resultwriter._execute_command("exit 0")
        self.assertTrue(0==result["std_err"])


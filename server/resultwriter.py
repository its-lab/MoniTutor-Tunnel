#!/usr/bin/python
import subprocess


class ResultWriter:

    def __init__(self, rabbit_host, result_exchange, task_exchange,
                 icingacmd_path="/var/run/icinga2/cmd/icinga2.cmd"):
        self._config = {"rabbit_host": rabbit_host,
                        "result_exchange": result_exchange,
                        "task_exchange": task_exchange,
                        "icingacmd_path": icingacmd_path}

    def _message_callback(self, channel, method, properties, body):
        icingacmd_string = self._get_icingacmd_string(body)
        icingacmd_commandline_string = self._get_icingacmd_commandline_string(icingacmd_string)
        self._execute_command(icingacmd_commandline_string)

    def _get_icingacmd_string(self, check_result):
        if check_result["icingacmd_type"] == "PROCESS_SERVICE_CHECK_RESULT":
            icingacmd_string = "[{0}] PROCESS_SERVICE_CHECK_RESULT;{1};{2};{3};{4}" \
                .format(check_result["time"],
                        check_result["host"],
                        check_result["name"],
                        check_result["severity_code"],
                        check_result["message"])
        else:
            icingacmd_string = "[{0}] PROCESS_HOST_CHECK_RESULT;{1};{2};{3}" \
                .format(check_result["time"],
                        check_result["host"],
                        check_result["severity_code"],
                        check_result["message"])
        return icingacmd_string

    def _get_icingacmd_commandline_string(self, icingacmd_string):
        return "echo '"+icingacmd_string+"' >> "+self._config["icingacmd_path"]+";"

    def _execute_command(self, command_string):
        try:
            output = subprocess.check_output(command_string, shell=True)
            returncode = 0
        except subprocess.CalledProcessError as result:
            output = result.output
            returncode = result.returncode
        finally:
            return {"output": output, "returncode": returncode}

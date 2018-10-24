#!/usr/bin/python
import subprocess
import logging
from resultwriter import ResultWriter


class IcingaResultWriter(ResultWriter):

    def __init__(self, rabbit_host, result_exchange, task_exchange,
                 icingacmd_path="/var/run/icinga2/cmd/icinga2.cmd"):
        super(IcingaResultWriter, self).__init__(rabbit_host, result_exchange, task_exchange)
        self._config["icingacmd_path"] = icingacmd_path

    def _process_result(self, check_result):
        icingacmd_string = self._get_icingacmd_string(check_result)
        return self._get_icingacmd_commandline_string(icingacmd_string)

    def _get_icingacmd_string(self, check_result):
        if check_result["icingacmd_type"] == "PROCESS_SERVICE_CHECK_RESULT":
            username = check_result["hostname"].split("_")[0]
            icingacmd_string = "[{0}] PROCESS_SERVICE_CHECK_RESULT;{1};{5}_{2};{3};{4}" \
                .format(check_result["time"],
                        check_result["hostname"],
                        check_result["name"],
                        check_result["severity_code"],
                        check_result["output"],
                        username)
        else:
            icingacmd_string = "[{0}] PROCESS_HOST_CHECK_RESULT;{1};{2};{3}" \
                .format(check_result["time"],
                        check_result["hostname"],
                        check_result["severity_code"],
                        check_result["output"])
        return icingacmd_string

    def _get_icingacmd_commandline_string(self, icingacmd_string):
        return "echo '"+icingacmd_string+"' >> "+self._config["icingacmd_path"]+";"

    def _write_result(self, command_string):
        logging.info("Execute command: "+command_string)
        try:
            output = subprocess.check_output(command_string, shell=True)
            returncode = 0
        except subprocess.CalledProcessError as result:
            output = result.output
            returncode = result.returncode
        finally:
            logging.debug("Outut: "+output+"; code: "+str(returncode))
            return {"output": output, "returncode": returncode}

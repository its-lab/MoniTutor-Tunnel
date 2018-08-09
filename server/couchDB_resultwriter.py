#!/usr/bin/python
import logging
from resultwriter import ResultWriter
from cloudant.client import CouchDB


class CouchDbResultWriter(ResultWriter):

    def __init__(self, rabbit_host, result_exchange, task_exchange,
                 couch_db_host="http://couchdb:5984",
                 couch_db_database="monitutor-results",
                 couch_db_user=None,
                 couch_db_password=None):
        super(CouchDbResultWriter, self).__init__(rabbit_host, result_exchange, task_exchange)
        admin_party = False
        if(couch_db_user is None or couch_db_password is None):
            admin_party = True
            logging.info("Start couchDB connection in admin party mode")
        self._couch_client = CouchDB(couch_db_user,
                                     couch_db_password,
                                     admin_party=admin_party,
                                     url=couch_db_host,
                                     connect=True)
        self._couch_session = self._couch_client.session()
        self._database_name = couch_db_database
        self._init_couchDB()

    def stop(self):
        super(CouchDbResultWriter, self).stop()
        self._couch_client.disconnect()

    def _process_result(self, check_result):
        return check_result

    def _write_result(self, result):
        logging.info("Write result: "+str(result))
        self._add_check_to_history(result)
        self._update_check_object(result)

    def _add_check_to_history(self, check_result):
        hostname = check_result["hostname"]
        if check_result["icingacmd_type"] == "PROCESS_SERVICE_CHECK_RESULT":
            check_result["object_id"] = hostname+"_"+check_result["check"]["name"]
        else:
            check_result["object_id"] = hostname
        self._database.create_document(check_result)
        del check_result["object_id"]

    def _update_check_object(self, check_result):
        hostname = check_result["hostname"]
        if check_result["icingacmd_type"] == "PROCESS_SERVICE_CHECK_RESULT":
            check_result["_id"] = hostname+"_"+check_result["check"]["name"]
        else:
            check_result["_id"] = hostname
        if check_result["_id"] in self._database:
            existing_document = self._database[check_result["_id"]]
            for key in check_result.viewkeys() & dict(existing_document).viewkeys():
                logging.info("existing_doucument." + key + "=check_result." +
                             key + " with value: " + str(check_result[key]))
                existing_document[key] = check_result[key]
            existing_document.save()
        else:
            self._database.create_document(check_result)

    def _init_couchDB(self):
        try:
            self._database = self._couch_client[self._database_name]
        except KeyError:
            logging.info("Create database "+self._database_name)
            self._database = self._couch_client.create_database(self._database_name)
            logging.info("Set revision limit of database "+self._database_name+"to 5")
            self._database.set_revision_limit(5)
        design_doc = self._database.get_design_document("results")
        check_result_history_map_function = """function(doc){
  var time, output, hostname, severity, check_name, username;
  if(doc.icingacmd_type == "PROCESS_SERVICE_CHECK_RESULT" && doc.object_id){
    hostname = doc.hostname.split("_")[1];
    username = doc.hostname.split("_")[0];
    check_name = doc.check.name;
    time = new Date(Number(doc.time)*1000);
    output = doc.output;
    severity = doc.severity_code;
    scenario_name = doc.check.scenario_name;
    emit([username, scenario_name, check_name, time], {output: output, severity: severity});
  }
}"""
        check_results_map_function = """function(doc){
  var time, output, hostname, severity, check_name, username;
  if(doc.icingacmd_type == "PROCESS_SERVICE_CHECK_RESULT" && !doc.object_id){
    hostname = doc.hostname.split("_")[1];
    username = doc.hostname.split("_")[0];
    check_name = doc.check.name;
    time = new Date(Number(doc.time)*1000);
    output = doc.output;
    severity = doc.severity_code;
    scenario_name = doc.check.scenario_name;
    emit([username, check_name], {output: output, severity: severity, time: time, scenario_name: scenario_name});
  }
}"""
        host_status_history_map_function = """function(doc){
  var time, output, hostname, severity, username;
  if(doc.icingacmd_type == "PROCESS_HOST_CHECK_RESULT" && doc.object_id){
    hostname = doc.hostname.split("_")[1];
    username = doc.hostname.split("_")[0];
    time = new Date(Number(doc.time)*1000);
    output = doc.output;
    severity = doc.severity_code;
    emit([username, hostname, time], {output: output, severity: severity});
  }
}"""
        host_status_map_function = """function(doc){
  var time, output, hostname, severity, username;
  if(doc.icingacmd_type == "PROCESS_HOST_CHECK_RESULT" && !doc.object_id){
    hostname = doc.hostname.split("_")[1];
    username = doc.hostname.split("_")[0];
    time = new Date(Number(doc.time)*1000);
    output = doc.output;
    severity = doc.severity_code;
    emit([username, hostname], {output: output, severity: severity, time: time});
  }
}"""
        severity_map_function = """function(doc){
  var time, output, hostname, severity, check_name, username;
  if(doc.icingacmd_type == "PROCESS_SERVICE_CHECK_RESULT" && doc.object_id){
    hostname = doc.hostname.split("_")[1];
    username = doc.hostname.split("_")[0];
    check_name = doc.check.name;
    time = new Date(Number(doc.time)*1000);
    output = doc.output;
    severity = doc.severity_code;
    scenario_name = doc.check.scenario_name
    emit([username, check_name, scenario_name, time], severity);
  }
}"""
        scenario_severity_map_function = """function(doc){
  var time, output, hostname, severity, check_name, username;
  if(doc.icingacmd_type == "PROCESS_SERVICE_CHECK_RESULT" && doc.object_id){
    hostname = doc.hostname.split("_")[1];
    username = doc.hostname.split("_")[0];
    check_name = doc.check.name;
    time = new Date(Number(doc.time)*1000);
    output = doc.output;
    severity = doc.severity_code;
    scenario_name = doc.check.scenario_name
    emit([scenario_name, username,  check_name, time], severity);
  }
}"""
        severity_reduce_function = """function(keys, values, rereduce){
  if (rereduce) {
    return values.reduce(function(a, b){return Math.min(a, b)}, 2);
  } else {
    return Math.min.apply(null, values);
  }
}"""

        successful_checks_map_function = """function(doc){
  var time, output, hostname, severity, check_name, username;
  if(doc.icingacmd_type == "PROCESS_SERVICE_CHECK_RESULT"
     && doc.object_id
     && doc.severity_code == 0){
    username = doc.hostname.split("_")[0];
    check_name = doc.check.name;
    severity = doc.severity_code;
    scenario_name = doc.check.scenario_name
    emit([scenario_name, username,  check_name], severity);
  }
}"""

        if "check_result_history" not in design_doc.list_views():
            design_doc.add_view("check_result_history", check_result_history_map_function)
        if "check_results" not in design_doc.list_views():
            design_doc.add_view("check_results", check_results_map_function)
        if "host_status_history" not in design_doc.list_views():
            design_doc.add_view("host_status_history", host_status_history_map_function)
        if "host_status" not in design_doc.list_views():
            design_doc.add_view("host_status", host_status_map_function)
        if "severity" not in design_doc.list_views():
            design_doc.add_view("severity",
                                severity_map_function,
                                reduce_func=severity_reduce_function)
        if "scenario_severity" not in design_doc.list_views():
            design_doc.add_view("scenario_severity",
                                scenario_severity_map_function,
                                reduce_func=severity_reduce_function)
        if "successful_checks" not in design_doc.list_views():
            design_doc.add_view("successful_checks",
                                successful_checks_map_function,
                                reduce_func='_count')
        design_doc.save()

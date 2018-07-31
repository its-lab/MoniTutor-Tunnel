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
        self._database.create_document(result)

    def _init_couchDB(self):
        try:
            self._database = self._couch_client[self._database_name]
        except KeyError:
            logging.info("Create database "+self._database_name)
            self._database = self._couch_client.create_database(self._database_name)
        design_doc = self._database.get_design_document("results")
        check_results_map_function = """function(doc){
  var time, output, hostname, severity, check_name, username;
  if(doc.icingacmd_type == "PROCESS_SERVICE_CHECK_RESULT"){
    hostname = doc.hostname.split("_")[1];
    username = doc.hostname.split("_")[0];
    check_name = doc.check.name;
    time = new Date(Number(doc.time)*1000);
    output = doc.output;
    severity = doc.severity_code;
    emit([username, check_name, time], {output: output, severity: severity});
  }
}"""
        host_status_map_function = """function(doc){
  var time, output, hostname, severity, username;
  if(doc.icingacmd_type == "PROCESS_HOST_CHECK_RESULT"){
    hostname = doc.hostname.split("_")[1];
    username = doc.hostname.split("_")[0];
    time = new Date(Number(doc.time)*1000);
    output = doc.output;
    severity = doc.severity_code;
    emit([username, hostname, time], {output: output, severity: severity});
  }
}"""
        severity_map_function = """function(doc){
  var time, output, hostname, severity, check_name, username;
  if(doc.icingacmd_type == "PROCESS_SERVICE_CHECK_RESULT"){
    hostname = doc.hostname.split("_")[1];
    username = doc.hostname.split("_")[0];
    check_name = doc.check.name;
    time = new Date(Number(doc.time)*1000);
    output = doc.output;
    severity = doc.severity_code;
    emit([username, check_name, time], severity);
  }
}"""
	severity_reduce_function = """function(keys, values, rereduce){
  if (rereduce) {
    return values.reduce(function(a, b){return Math.min(a, b)}, 2);
  } else {
    return Math.min.apply(null, values);
  }
}"""
        if "check_results" not in design_doc.list_views():
            design_doc.add_view("check_results", check_results_map_function)
        if "host_status" not in design_doc.list_views():
            design_doc.add_view("host_status", host_status_map_function)
        if "severity" not in design_doc.list_views():
            design_doc.add_view("severity", severity_map_function, reduce_func=severity_reduce_function)
	design_doc.save()

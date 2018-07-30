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
        try:
            self._database = self._couch_client[couch_db_database]
        except KeyError:
            self._database = self._couch_client.create_database(couch_db_database)
            logging.info("Create database "+couch_db_database)

    def stop(self):
        super(CouchDbResultWriter, self).stop()
        self._couch_client.disconnect()

    def _process_result(self, check_result):
        return check_result

    def _write_result(self, result):
        self._database.create_document(result)

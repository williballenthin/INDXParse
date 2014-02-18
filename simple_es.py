import json
import threading
import time
from Queue import Queue
from Queue import Empty
import logging

import requests


class Elasticsearch(object):
    def __init__(self, host, port=9200, resource_prefix="", username=None, password=None, is_https=False, validate_certs=True):
        self._host = host
        self._port = port
        self._resource_prefix = resource_prefix
        self._username = username
        self._password = password
        self._is_https = is_https
        self._validate_certs = validate_certs

        self._session = requests.Session()

        if username is not None and password is not None:
            self._session.auth = (username, password)
        elif username is not None or password is not None:
            raise ValueError("Username AND password must be provided if one is provided")

        self._session.verify = self._validate_certs

        if is_https:
            self._url = "https://"
        else:
            self._url = "http://"
        self._url += "%s:%s%s" % (self._host, self._port, self._resource_prefix)

    @staticmethod
    def get_argparse_args():
        return [
                (["--port"],            {"action":"store",      "dest":"es_port",            "default":"9200", "help":"Port of Elasticsearch"}),
                (["--resource_prefix"], {"action":"store",      "dest":"es_resource_prefix", "default":"",     "help":"Resource prefix for Elasticsearch"}),
                (["--username"],        {"action":"store",      "dest":"es_username",        "help":"Basic Auth username for Elasticsearch"}),
                (["--password"],        {"action":"store",      "dest":"es_password",        "help":"Basic Auth password for Elasticsearch"}),
                (["--https"],           {"action":"store_true", "dest":"es_is_https",        "help":"Use HTTPS for Elasticsearch"}),
                (["--no_validate_ssl"], {"action":"store_true", "dest":"es_no_validate_ssl", "help":"Do not validate Elasticsearch SSL cert"}),
                (["es_server"],         {"action":"store",       "help":"Servername of Elasticsearch"}),
                (["es_index"],          {"action":"store",       "help":"Elasticsearch index"})]

    @classmethod
    def from_argparse(cls, argparse):
       return cls(argparse.es_server,
                    port=argparse.es_port,
                    resource_prefix=argparse.es_resource_prefix,
                    username=argparse.es_username,
                    password=argparse.es_password,
                    is_https=argparse.es_is_https,
                    validate_certs=not argparse.es_no_validate_ssl)


    def index_document(self, index, type_, document):
        if not isinstance(document, basestring):
            document = json.dumps(document)
        return self._session.post(self._url + "/%s/%s" % (index, type_), data=json.dumps(document))

    def index_documents(self, index, type_, documents):
        action_and_metadata = json.dumps({"index": {"_index": index, "_type": type_}})

        body = ""
        for doc in documents:
            body += action_and_metadata + "\n"
            if isinstance(doc, basestring):
                body += doc + "\n"
            else:
                body += json.dumps(doc) + "\n"

        return self._session.post(self._url + "/%s/%s/_bulk" % (index, type_), data=body)


class IndexWorker(threading.Thread):
    def __init__(self, es, index, type_, queue, have_more, bulk_size=10, sleep_period=1.0):
        threading.Thread.__init__(self)
        threading.Thread.__init__(self)
        self._es = es
        self._index = index
        self._type = type_
        self._queue = queue
        self._have_more = have_more
        self._bulk_size = bulk_size
        self._logger = logging.getLogger("IndexWorker-%s" % (self.getName()))
        self._sleep_period = sleep_period

    def run(self):
        while True:
            items = []

            self._logger.debug("About %d items outstanding in the queue", self._queue.qsize())
            for _ in range(self._bulk_size):
                try:
                    self._logger.debug("Adding item to set")
                    items.append(self._queue.get(block=False))
                except Empty:
                    self._logger.debug("Queue empty")
                    if not self._have_more.is_set():
                        self._logger.debug("No more items to come")
                        if len(items) > 0:
                            self._logger.debug("Indexing final %d items", len(items))
                            r = self._es.index_documents(self._index, self._type, items)
                            if r.status_code != 200:
                                self._logger.error(r)
                                return
                        return
                    if not len(items) > 0:
                        self._logger.debug("Sleeping for %f seconds", self._sleep_period)
                        time.sleep(self._sleep_period)
                        break

            if len(items) > 0:
                self._logger.debug("Indexing %d items", len(items))
                r = self._es.index_documents(self._index, self._type, items)
                if r.status_code != 200:
                    self._logger.error(r)
                    return


class IndexWorkpool(object):
    def __init__(self, es, index, type_, workpool_size=10, bulk_size=10):
        self._es = es
        self._index = index
        self._type = type_
        self._workpool_size = workpool_size
        self._bulk_size = bulk_size

        self._queue = Queue()
        self._have_more = threading.Event()
        self._have_more.set()

        self._pool = set()
        for _ in range(self._workpool_size):
            w = IndexWorker(self._es, self._index, self._type, self._queue, self._have_more, bulk_size=self._bulk_size)
            w.setDaemon(True)
            w.start()
            self._pool.add(w)

    def index_document(self, document):
        if not self._have_more.is_set():
            raise ValueError("Workpool already closed.")
        self._queue.put(document)

    def get_queue_size(self):
        return self._queue.qsize()

    def close(self):
        self._have_more.clear()
        for w in self._pool:
            w.join()

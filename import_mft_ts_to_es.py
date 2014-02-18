#!/usr/bin/python

# This file is part of INDXParse.
#
# Copyright 2014 Willi Ballenthin <william.ballenthin@mandiant.com>
# while at FireEye <http://www.fireeye.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import types
import logging
import json
import datetime
import time

import argparse

from BinaryParser import Mmap
from MFT import MFTEnumerator
from MFT import ATTR_TYPE
from MFT import IndexRootHeader

from simple_es import Elasticsearch
from simple_es import IndexWorkpool


def main():
    parser = argparse.ArgumentParser(description="Index MFT record timestamps using Elasticsearch.")
    parser.add_argument("-v", action="store_true", dest="verbose",
                        help="Print debugging information")
    for args, kwargs in Elasticsearch.get_argparse_args():
        parser.add_argument(*args, **kwargs)
    parser.add_argument("--workpool_size", action="store", default=4, dest="wp_workpool_size", help="Number of parallel upload threads to spawn.")
    parser.add_argument("--bulk_size", action="store", default=50, dest="wp_bulk_size", help="Number of documents to upload in one chunk.")
    parser.add_argument("filename", action="store", help="Input MFT file path")
    results = parser.parse_args()

    if results.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logger = logging.getLogger("import_mft_ts_to_es")
    num_allowed_queued_items = 4 * results.wp_workpool_size * results.wp_bulk_size

    with Mmap(results.filename) as buf:
        enum = MFTEnumerator(buf)
        es = Elasticsearch.from_argparse(results)
        es_pool = IndexWorkpool(es, results.es_index, "mft_record", workpool_size=results.wp_workpool_size, bulk_size=results.wp_bulk_size)

        class MFTEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat("T") + "Z"
                elif isinstance(obj, types.GeneratorType):
                    return [o for o in obj]
                return json.JSONEncoder.default(self, obj)

        for record, record_path in enum.enumerate_paths():
            logger.debug("Generating record %d", record.inode)
            fn = record.filename_information()
            si = record.standard_information()

            ts_attributes = [("filename information", fn, record_path), ("standard information", si, record_path)]

            indxroot = record.attribute(ATTR_TYPE.INDEX_ROOT)
            if indxroot and indxroot.non_resident() == 0:
                irh = IndexRootHeader(indxroot.value(), 0, False)
                for e in irh.node_header().entries():
                    fn = e.filename_information()
                    fn_filename = fn.filename()
                    ts_attributes.append(("indx", fn, record_path + "\\" + fn_filename))

                for e in irh.node_header().slack_entries():
                    fn = e.filename_information()
                    fn_filename = fn.filename()
                    ts_attributes.append(("slack_indx", fn, record_path + "\\" + fn_filename))


            for attr_type, attr, path in ts_attributes:
                if attr is None:
                    continue
                for ts_type in ["created", "accessed", "modified", "changed"]:
                    ts_accessor = getattr(attr, ts_type + "_time")
                    try:
                        ts = ts_accessor()
                    except ValueError:
                        continue
                    es_pool.index_document(json.dumps({
                        "@timestamp": ts,
                        "source": attr_type.replace(" ", "_"),
                        "ts_type": ts_type,
                        "message": path
                        }, cls=MFTEncoder))

            if record.inode % 100 == 0:
                logger.info("Generated %d records", record.inode)
                logger.info("About %d outstanding records in the index queue", es_pool.get_queue_size())

            while es_pool.get_queue_size() > num_allowed_queued_items:
                logger.info("Sleeping while queue is large (%d)", es_pool.get_queue_size())
                time.sleep(1)

        es_pool.close()


if __name__ == "__main__":
    main()

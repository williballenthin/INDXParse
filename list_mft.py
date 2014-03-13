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
#
#
# This is a straightforward script; the complexity comes about in supporting
#  a variety of output formats. The default output (Bodyfile), is by far
#  the fastest (by a factor of about two). The user defined formats are
#  implemented with Jinja2 templating. This makes our job fairly easy.
#  The final option is JSON output.
#
# TODO:
#   - use logging instead of #-prefixed comment lines
#   - display inactive record tags

import types
import sys
import logging
import calendar
import json
import datetime

from jinja2 import Environment
import argparse

from BinaryParser import Mmap
from MFT import Cache
from MFT import MFTEnumerator
from MFT import ATTR_TYPE
from MFT import MREF
from MFT import IndexRootHeader
from MFT import StandardInformationFieldDoesNotExist
from get_file_info import make_model
from Progress import NullProgress
from Progress import ProgressBarProgress


def format_bodyfile(path, size, inode, owner_id, info, attributes=None):
    """
    Format a single line of Bodyfile output.
    """
    if not attributes:
        attributes = []
    try:
        modified = int(calendar.timegm(info.modified_time().timetuple()))
    except (ValueError, AttributeError):
        modified = int(calendar.timegm(datetime.datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        accessed = int(calendar.timegm(info.accessed_time().timetuple()))
    except (ValueError, AttributeError):
        accessed = int(calendar.timegm(datetime.datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        changed = int(calendar.timegm(info.changed_time().timetuple()))
    except (ValueError, AttributeError):
        changed = int(calendar.timegm(datetime.datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        created = int(calendar.timegm(info.created_time().timetuple()))
    except (ValueError, AttributeError):
        created = int(calendar.timegm(datetime.datetime.min.timetuple()))
    attributes_text = ""
    if len(attributes) > 0:
        attributes_text = " (%s)" % (", ".join(attributes))
    return u"0|%s|%s|0|%d|0|%s|%s|%s|%s|%s\n" % (path + attributes_text, inode,
                                                 owner_id,
                                                 size, accessed, modified,
                                                 changed, created)


def output_mft_record(mft_enumerator, record, prefix):
    """
    Print to STDOUT all the Bodyfile formatted lines
      associated with a single record. This includes
      a line for standard information, filename information,
      and any resident directory index entries.
    """
    tags = []
    if not record.is_active():
        tags.append("inactive")

    path = prefix + "\\" + mft_enumerator.get_path(record)
    si = record.standard_information()
    fn = record.filename_information()

    if not record.is_active() and not fn:
        return

    inode = record.mft_record_number()
    if record.is_directory():
        size = 0
    else:
        data_attr = record.data_attribute()
        if data_attr and data_attr.non_resident() > 0:
            size = data_attr.data_size()
        elif fn:
            size = fn.logical_size()
        else:
            size = 0

    ADSs = []  # list of (name, size)
    for attr in record.attributes():
        if attr.type() != ATTR_TYPE.DATA or len(attr.name()) == 0:
            continue
        if attr.non_resident() > 0:
            size = attr.data_size()
        else:
            size = attr.value_length()
        ADSs.append((attr.name(), size))

    si_index = 0
    if si:
        try:
            si_index = si.security_id()
        except StandardInformationFieldDoesNotExist:
            pass

    indices = []  # list of (filename, size, reference, info)
    slack_indices = []  # list of (filename, size, reference, info)
    indxroot = record.attribute(ATTR_TYPE.INDEX_ROOT)
    if indxroot and indxroot.non_resident() == 0:
        # TODO(wb): don't use IndxRootHeader
        irh = IndexRootHeader(indxroot.value(), 0, False)
        for e in irh.node_header().entries():
            indices.append((e.filename_information().filename(),
                            e.mft_reference(),
                            e.filename_information().logical_size(),
                            e.filename_information()))

        for e in irh.node_header().slack_entries():
            slack_indices.append((e.filename_information().filename(),
                                  e.mft_reference(),
                                  e.filename_information().logical_size(),
                                  e.filename_information()))

    # si
    if si:
        try:
            print format_bodyfile(path, size, inode, si_index, si, tags),
        except UnicodeEncodeError:
            print "# failed to print: %s" % (list(path))

    # fn
    if fn:
        tags = ["filename"]
        if not record.is_active():
            tags.append("inactive")
        try:
            print format_bodyfile(path, size, inode, si_index, fn, tags),
        except UnicodeEncodeError:
            print "# failed to print: %s" % (list(path))

    # ADS
    for ads in ADSs:
        tags = []
        if not record.is_active():
            tags.append("inactive")
        try:
            print format_bodyfile(path + ":" + ads[0], ads[1], inode, si_index, si or {}, tags),
        except UnicodeEncodeError:
            print "# failed to print: %s" % (list(path))

    # INDX
    for indx in indices:
        tags = ["indx"]
        try:
            print format_bodyfile(path + "\\" + indx[0], indx[1], MREF(indx[2]), 0, indx[3], tags),
        except UnicodeEncodeError:
            print "# failed to print: %s" % (list(path))

    for indx in slack_indices:
        tags = ["indx", "slack"]
        try:
            print format_bodyfile(path + "\\" + indx[0], indx[1], MREF(indx[2]), 0, indx[3], tags),
        except UnicodeEncodeError:
            print "# failed to print: %s" % (list(path))


def unixtimestampformat(value):
    """
    A custom Jinja2 filter for converting a datetime.datetime
      a UNIX timestamp integer.
    """
    if value is None:
        return 0
    return int(calendar.timegm(value.timetuple()))


def get_default_template(env):
    """
    Return a Jinja2 Template instance that formats an
      MFT record into bodyfile format.
    Slower than the format_bodyfile() function above, so
      this format is provided here for reference.
    """
    return env.from_string(
"""\
{% if record.standard_information and record.filename_information %}
0|{{ prefix }}{{ record.path }}|{{ record.inode }}|0|{{ record.standard_information.owner_id }}|0|{{ record.size }}|{{ record.standard_information.accessed|unixtimestampformat }}|{{ record.standard_information.modified|unixtimestampformat }}|{{ record.standard_information.changed|unixtimestampformat }}|{{ record.standard_information.created|unixtimestampformat }}
{% endif %}
{% if record.standard_information and record.filename_information %}
0|{{ prefix }}{{ record.path }} (filename)|{{ record.inode }}|0|{{ record.standard_information.owner_id }}|0|{{ record.size }}|{{ record.filename_information.accessed|unixtimestampformat }}|{{ record.filename_information.modified|unixtimestampformat }}|{{ record.filename_information.changed|unixtimestampformat }}|{{ record.filename_information.created|unixtimestampformat }}
{% endif %}
{% for e in record.indx_entries %}
0|{{ prefix }}{{ record.path }}\\{{ e.name }} (INDX)|{{ e.inode }}|0|0|0|{{ e.logical_size }}|{{ e.accessed|unixtimestampformat }}|{{ e.modified|unixtimestampformat }}|{{ e.changed|unixtimestampformat }}|{{ e.created|unixtimestampformat }}
{% endfor %}
{% for e in record.slack_indx_entries %}
0|{{ prefix }}{{ record.path }}\\{{ e.name }} (slack-INDX)|{{ e.inode }}|0|0|0|{{ e.logical_size }}|{{ e.accessed|unixtimestampformat }}|{{ e.modified|unixtimestampformat }}|{{ e.changed|unixtimestampformat }}|{{ e.created|unixtimestampformat }}
{% endfor %}
""")


def main():
    parser = argparse.ArgumentParser(description='Parse MFT '
                                     'filesystem structures.')
    parser.add_argument('-c', action="store", metavar="cache_size", type=int,
                        dest="cache_size", default=1024,
                        help="Size of cache.")
    parser.add_argument('-p', action="store", metavar="prefix",
                        nargs=1, dest="prefix", default="\\.",
                        help="Prefix paths with `prefix` rather than \\.\\")
    parser.add_argument('-v', action="store_true", dest="verbose",
                        help="Print debugging information")
    parser.add_argument('--progress', action="store_true",
                        dest="progress",
                        help="Update a status indicator on STDERR "
                        "if STDOUT is redirected")
    parser.add_argument('--format', action="store", metavar="format",
                        nargs=1, dest="format",
                        help="Output format specification")
    parser.add_argument('--format_file', action="store", metavar="format_file",
                        nargs=1, dest="format_file",
                        help="File containing output format specification")
    parser.add_argument('--json', action="store_true", dest="json",
                        help="Output in JSON format")
    parser.add_argument('-f', action="store", metavar="regex",
                        nargs=1, dest="filter",
                        help="Only consider entries whose path "
                        "matches this regular expression")
    parser.add_argument('filename', action="store",
                        help="Input MFT file path")
    results = parser.parse_args()
    use_default_output = True

    if results.verbose:
        logging.basicConfig(level=logging.DEBUG)

    env = Environment(trim_blocks=True, lstrip_blocks=True)
    env.filters["unixtimestampformat"] = unixtimestampformat

    flags_count = 0
    if results.format:
        flags_count += 1
        template = env.from_string(results.format[0])
    if results.format_file:
        flags_count += 1
        with open(results.format_file[0], "rb") as f:
            template = env.from_string(f.read())
    if results.json:
        flags_count += 1
        pass

    if flags_count > 1:
        sys.stderr.write("Only one of --format, --format_file, --json may be provided.\n")
        sys.exit(-1)
    elif flags_count == 1:
        use_default_output = False
    elif flags_count == 0:
        flags_count += 1
        template = get_default_template(env)
        use_default_output = True

    if results.progress:
        progress_cls = ProgressBarProgress
    else:
        progress_cls = NullProgress

    with Mmap(results.filename) as buf:
        record_cache = Cache(results.cache_size)
        path_cache = Cache(results.cache_size)

        enum = MFTEnumerator(buf,
                             record_cache=record_cache,
                             path_cache=path_cache)
        progress = progress_cls(enum.len())
        if use_default_output:
            for record, record_path in enum.enumerate_paths():
                output_mft_record(enum, record, results.prefix[0])
                progress.set_current(record.inode)
        elif results.json:
            class MFTEncoder(json.JSONEncoder):
                def default(self, obj):
                    if isinstance(obj, datetime.datetime):
                        return obj.isoformat("T") + "Z"
                    elif isinstance(obj, types.GeneratorType):
                        return [o for o in obj]
                    return json.JSONEncoder.default(self, obj)
            print("[")
            for record, record_path in enum.enumerate_paths():
                m = make_model(record, record_path)
                print(json.dumps(m, cls=MFTEncoder, indent=2) + ",")
                progress.set_current(record.inode)
            print("]")
        else:
            for record, record_path in enum.enumerate_paths():
                sys.stdout.write(template.render(record=make_model(record, record_path),
                                                 prefix=results.prefix[0]) + "\n")
                progress.set_current(record.inode)
        progress.set_complete()


if __name__ == "__main__":
    main()

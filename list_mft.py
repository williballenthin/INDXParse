# TODO:
#   - display inactive record tags
#   - add CSV output
#   - add custom template support

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
from get_file_info import make_model
from Progress import NullProgress
from Progress import ProgressBarProgress


def unixtimestampformat(value):
    if value is None:
        return 0
    return int(calendar.timegm(value.timetuple()))


def get_default_template(env):
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
    elif flags_count == 0:
        flags_count += 1
        template = get_default_template(env)

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
        if results.json:
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
                                                 prefix=results.prefix[0]))
                progress.set_current(record.inode)
        progress.set_complete()


if __name__ == "__main__":
    main()

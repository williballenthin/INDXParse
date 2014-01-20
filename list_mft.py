# TODO:
#   - display inactive record tags
#   - add CSV output
#   - add custom template support

import sys
import logging
import calendar

from jinja2 import Environment
import argparse

from BinaryParser import Mmap
from MFT import Cache
from MFT import MFTEnumerator
from get_file_info import make_model


def unixtimestampformat(value):
    if value is None:
        return 0
    return int(calendar.timegm(value.timetuple()))


def get_default_template(env):
    return env.from_string(
"""\
{% if record.standard_information and record.filename_information %}\
0|{{ record.path }}|{{ record.record_num }}|0|{{ record.standard_information.owner_id }}|0|{{ record.size }}|{{ record.standard_information.accessed|unixtimestampformat }}|{{ record.standard_information.modified|unixtimestampformat }}|{{ record.standard_information.changed|unixtimestampformat }}|{{ record.standard_information.created|unixtimestampformat }}
{% endif %}\
{% if record.standard_information and record.filename_information %}\
0|{{ record.path }} (filename)|{{ record.record_num }}|0|{{ record.standard_information.owner_id }}|0|{{ record.size }}|{{ record.filename_information.accessed|unixtimestampformat }}|{{ record.filename_information.modified|unixtimestampformat }}|{{ record.filename_information.changed|unixtimestampformat }}|{{ record.filename_information.created|unixtimestampformat }}
{% endif %}\
{% for e in record.indx_entries %}\
0|{{ record.path }}\\{{ e.name }} (INDX)|{{ e.record_num }}|0|0|0|{{ e.logical_size }}|{{ e.accessed|unixtimestampformat }}|{{ e.modified|unixtimestampformat }}|{{ e.changed|unixtimestampformat }}|{{ e.created|unixtimestampformat }}
{% endfor %}\
{% for e in record.slack_indx_entries %}\
0|{{ record.path }}\\{{ e.name }} (slack-INDX)|{{ e.record_num }}|0|0|0|{{ e.logical_size }}|{{ e.accessed|unixtimestampformat }}|{{ e.modified|unixtimestampformat }}|{{ e.changed|unixtimestampformat }}|{{ e.created|unixtimestampformat }}
{% endfor %}
""")


def main():
    parser = argparse.ArgumentParser(description='Parse MFT '
                                     'filesystem structures.')
    parser.add_argument('-f', action="store", metavar="regex",
                        nargs=1, dest="filter",
                        help="Only consider entries whose path "
                        "matches this regular expression")
    parser.add_argument('-c', action="store", metavar="cache_size", type=int,
                        dest="cache_size", default=1024,
                        help="Size of cache.")
    parser.add_argument('-p', action="store", metavar="prefix",
                        nargs=1, dest="prefix", default="\\.",
                        help="Prefix paths with `prefix` rather than \\.\\")
    parser.add_argument('--progress', action="store_true",
                        dest="progress",
                        help="Update a status indicator on STDERR "
                        "if STDOUT is redirected")
    parser.add_argument('-v', action="store_true", dest="verbose",
                        help="Print debugging information")
    parser.add_argument('filename', action="store",
                        help="Input MFT file path")

    results = parser.parse_args()

    if results.verbose:
        logging.basicConfig(level=logging.DEBUG)

    env = Environment(trim_blocks=True, lstrip_blocks=True)
    env.filters["unixtimestampformat"] = unixtimestampformat

    template = get_default_template(env)
    with Mmap(results.filename) as buf:
        record_cache = Cache(results.cache_size)
        path_cache = Cache(results.cache_size)

        enum = MFTEnumerator(buf,
                             record_cache=record_cache,
                             path_cache=path_cache)
        for record, record_path in enum.enumerate_paths():
            sys.stdout.write(template.render(record=make_model(record, record_path)))


if __name__ == "__main__":
    main()

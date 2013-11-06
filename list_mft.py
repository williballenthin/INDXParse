from MFT import MFTEnumerator

import logging
import calendar
from datetime import datetime

import argparse

from BinaryParser import Mmap
from MFT import Cache
from MFT import ATTR_TYPE
from MFT import MREF
from MFT import IndexRootHeader
from MFT import StandardInformationFieldDoesNotExist


def format_bodyfile(path, size, inode, owner_id, info, attributes=None):
    if not attributes:
        attributes = []
    try:
        modified = int(calendar.timegm(info.modified_time().timetuple()))
    except (ValueError, AttributeError):
        modified = int(calendar.timegm(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        accessed = int(calendar.timegm(info.accessed_time().timetuple()))
    except (ValueError, AttributeError):
        accessed = int(calendar.timegm(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        changed  = int(calendar.timegm(info.changed_time().timetuple()))
    except (ValueError, AttributeError):
        changed = int(calendar.timegm(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        created  = int(calendar.timegm(info.created_time().timetuple()))
    except (ValueError, AttributeError):
        created = int(calendar.timegm(datetime.min.timetuple()))
    attributes_text = ""
    if len(attributes) > 0:
        attributes_text = " (%s)" % (", ".join(attributes))
    return u"0|%s|%s|0|%d|0|%s|%s|%s|%s|%s\n" % (path + attributes_text, inode,
                                                 owner_id,
                                                 size, accessed, modified,
                                                 changed, created)


def output_mft_record(mft_enumerator, record, prefix):
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

    with Mmap(results.filename) as buf:
        record_cache = Cache(results.cache_size)
        path_cache = Cache(results.cache_size)

        enum = MFTEnumerator(buf,
                             record_cache=record_cache,
                             path_cache=path_cache)
        for record, record_path in enum.enumerate_paths():
            output_mft_record(enum, record, results.prefix)

if __name__ == "__main__":
    main()

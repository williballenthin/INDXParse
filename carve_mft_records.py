#!/usr/bin/env python2
'''
Carve MFT records from arbitrary binary data.

author: Willi Ballenthin
email: william.ballenthin@fireeye.com
'''
import os
import sys
import mmap
import array
import logging
import contextlib

import argparse

import MFT


logger = logging.getLogger(__name__)


def sizeof_fmt(num, suffix='B'):
    '''
    via: http://stackoverflow.com/a/1094933/87207
    '''

    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


class BadRecord(Exception): pass


def output_record(record_offset, record):
    ret = []

    ret.append(hex(record_offset))
    ret.append(record.filename_information().filename())

    data = record.data_attribute()
    ret.append(hex(data.allocated_size()))

    if data.non_resident() == 0:
        logger.warn('unexpected resident data')
        raise BadRecord()

    if data.allocated_size() == 0:
        logger.warn('unexpected zero length')
        raise BadRecord()
        
    for (offset, length) in data.runlist().runs():
        logger.debug('run offset: %s clusters, length: %s clusters (%s / %s in bytes)', offset, length, offset * 4096, length * 4096)

    off, size = list(data.runlist().runs())[0]
    ret.append(hex(off))
    ret.append(hex(size))

    print((','.join(ret)))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="A program.")
    parser.add_argument("input", type=str,
                        help="Path to input file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Disable all output but errors")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)

    HEADER = 'FILE0'
    total_size = os.path.getsize(args.input)

    count = 0
    with open(args.input, 'rb') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as m:
            offset = 0
            while True:
                offset = m.find(HEADER, offset)

                if offset == -1:
                    break

                if offset % 0x10 != 0:
                    offset += 1
                    continue

                buf = array.array('B', m[offset:offset+1024])
                record = MFT.MFTRecord(buf, 0, None)
                output_record(offset, record)
                count += 1

                if count % 1000 == 0:
                    logger.info('%s: found %d records over %s bytes (of %s total), %.2f complete',
                                hex(offset), count, sizeof_fmt(offset), sizeof_fmt(total_size),
                                float(offset)/total_size)
                offset += 1


if __name__ == "__main__":
    sys.exit(main())

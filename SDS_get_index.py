#!/bin/python

#    This file is part of INDXParse.
#
#   Copyright 2011-13 Will Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v.1.2
from SDS import SDS

def main():
    import sys
    import mmap
    import contextlib
    import argparse

    parser = argparse.ArgumentParser(description='Get an SDS record by index.')
    parser.add_argument('-v', action="store_true", dest="verbose",
                        help="Print debugging information")
    parser.add_argument('SDS', action="store",
                        help="Input SDS file path")
    parser.add_argument('index', action="store", type=int,
                        help="Entry index to fetch")
    results = parser.parse_args()

    with open(results.SDS, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            s = SDS(buf, 0, None)
            print "SDS"
            for e in s.sds_entries():
                print("  SDS_ENTRY")
                print(e.get_all_string(indent=2))

if __name__ == "__main__":
    main()

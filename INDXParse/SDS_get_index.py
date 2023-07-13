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
#
#   Portions of this file contributed by NIST are governed by the
#   following statement:
#
#   This software was developed at the National Institute of Standards
#   and Technology by employees of the Federal Government in the course
#   of their official duties. Pursuant to title 17 Section 105 of the
#   United States Code this software is not subject to copyright
#   protection and is in the public domain. NIST assumes no
#   responsibility whatsoever for its use by other parties, and makes
#   no guarantees, expressed or implied, about its quality,
#   reliability, or any other characteristic.
#
#   We would appreciate acknowledgement if the software is used.
#
#
#   Version v.1.2
from INDXParse.SDS import SDS


def main():
    import argparse
    import contextlib
    import mmap
    import sys

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
            print("SDS")
            for e in s.sds_entries():
                print("  SDS_ENTRY")
                print((e.get_all_string(indent=2)))

if __name__ == "__main__":
    main()

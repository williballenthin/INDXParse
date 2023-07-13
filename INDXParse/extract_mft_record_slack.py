#!/bin/python

#    This file is part of INDXParse.
#
#   Copyright 2014 Will Ballenthin <william.ballenthin@mandiant.com>
#                    while at FireEye <http://www.FireEye.com>
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
import sys

from INDXParse.BinaryParser import Mmap
from INDXParse.MFT import MFTEnumerator


def main():
    filename = sys.argv[1]

    with Mmap(filename) as buf:
        enum = MFTEnumerator(buf)
        for record in enum.enumerate_records():
            slack = record.slack_data()
            sys.stdout.write("\x00" * (1024 - len(slack)))
            sys.stdout.write(slack)


if __name__ == "__main__":
    main()

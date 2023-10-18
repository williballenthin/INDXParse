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
#   Alex Nelson, NIST, contributed to this file.  Contributions of NIST
#   are not subject to US Copyright.
import mmap
import sys

from indxparse.MFT import MFTEnumerator


def main() -> None:
    filename = sys.argv[1]

    with open(filename, "rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            enum = MFTEnumerator(mm)
            for record in enum.enumerate_records():
                slack = record.slack_data()
                sys.stdout.buffer.write(b"\x00" * (1024 - len(slack)))
                sys.stdout.buffer.write(slack)


if __name__ == "__main__":
    main()

import sys

from BinaryParser import Mmap
from MFT import MFTEnumerator
from MFT import Cache
from MFT import ATTR_TYPE
from MFT import MREF
from MFT import IndexRootHeader
from MFT import StandardInformationFieldDoesNotExist


def main():
    filename = sys.argv[1]

    with Mmap(filename) as buf:
        record_cache = Cache(1024)
        path_cache = Cache(1024)

        enum = MFTEnumerator(buf,
                             record_cache=record_cache,
                             path_cache=path_cache)
        for record in enum.enumerate_records():
            slack = record.slack()
            sys.stdout.write("\x00" * (1024 - len(slack)))
            sys.stdout.write(slack)


if __name__ == "__main__":
    main()

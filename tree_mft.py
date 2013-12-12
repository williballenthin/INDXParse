from MFT import MFTEnumerator

import mmap
import logging
import calendar
from datetime import datetime

import argparse

from MFT import Cache
from MFT import MFTTree


class Mmap(object):
    """
    Convenience class for opening a read-only memory map for a file path.
    """
    def __init__(self, filename):
        super(Mmap, self).__init__()
        self._filename = filename
        self._f = None
        self._mmap = None
        
    def __enter__(self):
        self._f = open(self._filename, "rb")
        self._mmap = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        return self._mmap

    def __exit__(self, type, value, traceback):
        self._mmap.close()
        self._f.close()


def main():
    parser = argparse.ArgumentParser(description='Parse MFT '
                                     'filesystem structures.')
    parser.add_argument('-c', action="store", metavar="cache_size", type=int,
                        dest="cache_size", default=1024,
                        help="Size of cache.")
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
        
        tree = MFTTree(buf)
        tree.build(record_cache=record_cache, path_cache=path_cache)

        def rec(node, prefix):
            print prefix + node.get_filename()
            for child in node.get_children():
                rec(child, prefix + "  ")
        
        rec(tree.get_root(), "")

if __name__ == "__main__":
    main()



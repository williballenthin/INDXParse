from MFT import NTATTR_STANDARD_INDEX_HEADER
from MFT import INDEX_ALLOCATION


def main():
    import sys
    import contextlib
    import mmap
    with open(sys.argv[1], "rb") as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            ofs = 0x0
            while ofs + 0x1000 <= len(buf):
                allocation = INDEX_ALLOCATION(buf, ofs, None)
                for entry in allocation.index().entries():
                    print("active|" + entry.filename_information().filename())
                for entry in allocation.index().slack_entries():
                    print("slack|" + entry.filename_information().filename())
                ofs += len(allocation)


if __name__ == "__main__":
    main()
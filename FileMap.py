#!/usr/bin/python

import sys
from struct import unpack_from as old_unpack_from
from struct import unpack_from as old_unpack
from struct import calcsize

from collections import OrderedDict
# From: http://code.activestate.com/recipes/577197-sortedcollection/
from SortedCollection import SortedCollection


MEGABYTE = 1024 * 1024


class LRUQueue(object):
    """
    LRUQueue is a data structure that orders objects by
      their insertion time, and supports an update/touch operation
      that resets an item to the newest slot.

    This is an example of a priority queue, ordered by
      insertion time, with explicit support for "touch".
    """
    def __init__(self, key=lambda n: n):
        """
        The `key` parameter may be provided if the
          items in the queue are complex.
        The `key` parameter should select a unique "id" field from
          each item.
        """
        super(LRUQueue, self).__init__()
        self._q = OrderedDict()
        self._key = key

    def push(self, v):
        k = self._key(v)
        self._q[k] = v

    def pop(self):
        return self._q.popitem(last=False)[1]

    def touch(self, v):
        """
        Reset the given value back to the newest slot.
        """
        k = self._key(v)
        del self._q[k]
        self._q[k] = v

    def size(self):
        return len(self._q)

    def __len__(self):
        return self.size()

    @staticmethod
    def test():
        q = LRUQueue()
        assert q.size() == 0
        assert len(q) == 0

        q.push(0)
        assert q.size() == 1
        assert len(q) == 1

        assert q.pop() == 0
        assert q.size() == 0
        assert len(q) == 0

        q.push(0)
        q.push(1)
        assert q.pop() == 0
        assert q.pop() == 1

        q.push(0)
        q.push(1)
        q.touch(0)
        assert q.pop() == 1
        assert q.pop() == 0

        q = LRUQueue(key=lambda n: n[0])
        q.push([0])
        assert q.pop() == [0]

        q.push([0])
        q.push([1])
        assert q.pop() == [0]
        assert q.pop() == [1]
        return True


class BoundedLRUQueue(object):
    """
    BoundedLRUQueue is a LRUQueue with a finite capacity.
      When an item is pushed that causes the capacity to be exceeded,
      the LRU item is automatically popped.

    Otherwise, this class behaves just like the LRUQueue.
    """
    def __init__(self, capacity, key=lambda n: n):
        """
        The `key` parameter may be provided if the
          items in the queue are complex.
        The `key` parameter should select a unique "id" field from
          each item.
        """
        super(BoundedLRUQueue, self).__init__()
        self._q = LRUQueue(key)
        self._capacity = capacity

    def push(self, v):
        self._q.push(v)
        if len(self._q) > self._capacity:
            return self._q.pop()

    def pop(self):
        return self._q.pop()

    def touch(self, v):
        self._q.touch(v)

    def size(self):
        return len(self._q)

    def __len__(self):
        return self.size()

    @staticmethod
    def test():
        q = BoundedLRUQueue(5)
        assert q.size() == 0
        assert len(q) == 0

        q.push(0)
        assert q.size() == 1
        assert len(q) == 1

        assert q.pop() == 0
        assert q.size() == 0
        assert len(q) == 0

        q.push(0)
        q.push(1)
        assert q.pop() == 0
        assert q.pop() == 1

        q.push(0)
        q.push(1)
        q.touch(0)
        assert q.pop() == 1
        assert q.pop() == 0

        q = BoundedLRUQueue(5, key=lambda n: n[0])
        q.push([0])
        assert q.pop() == [0]

        q.push([0])
        q.push([1])
        assert q.pop() == [0]
        assert q.pop() == [1]

        q = BoundedLRUQueue(2)
        assert q.push(0) is None
        assert q.push(1) is None
        assert q.push(2) == 0
        assert q.pop() == 1
        assert q.pop() == 2
        return True


class RangeCache(object):
    """
    RangeCache is a data structure that tracks a finite set of
      ranges (a range is a 2-tuple consisting of a numeric start
      and numeric length). New ranges can be added via the `push`
      method, and if such a call causes the capacity to be exceeded,
      then the "oldest" range is removed. The `get` method implements
      an efficient lookup for a single value that may be found within
      one of the ranges.
    """
    def __init__(self, capacity,
                 start_key=lambda o: o[0],
                 length_key=lambda o: o[1]):
        """
        @param key: A function that fetches the range start from an item.
        """
        super(RangeCache, self).__init__()
        self._ranges = SortedCollection(key=start_key)
        self._lru = BoundedLRUQueue(capacity, key=start_key)
        self._start_key = start_key
        self._length_key = length_key

    def push(self, o):
        """
        Add a range to the cache.

        If `key` is not provided to the constructor, then
          `o` should be a 3-tuple:
            - range start (numeric)
            - range length (numeric)
            - range item (object)
        """
        self._ranges.insert(o)
        popped = self._lru.push(o)
        if popped is not None:
            self._ranges.remove(popped)

    def touch(self, o):
        self._lru.touch(o)

    def get(self, value):
        """
        Search for the numeric `value` within the ranges
          tracked by this cache.
        @raise ValueError: if the value is not found in the range cache.
        """
        hit = self._ranges.find_le(value)
        if value < self._start_key(hit) + self._length_key(hit):
            return hit
        raise ValueError("%s not found in range cache" % value)

    @staticmethod
    def test():
        q = RangeCache(2)

        x = None
        try: x = q.get(0)
        except ValueError: pass
        assert x is None

        x = None
        try: x = q.get(1)
        except ValueError: pass
        assert x is None

        q.push((1, 1, [0]))

        x = None
        try: x = q.get(0)
        except ValueError: pass
        assert x is None

        assert q.get(1) == (1, 1, [0])
        assert q.get(1.99) == (1, 1, [0])
        x = None
        try: x = q.get(2.01)
        except ValueError: pass
        assert x is None

        q.push((3, 1, [1]))
        assert q.get(1) == (1, 1, [0])
        assert q.get(3) == (3, 1, [1])

        q.push((5, 1, [2]))
        x = None
        try: x = q.get(1)
        except ValueError: pass
        assert x is None

        assert q.get(3) == (3, 1, [1])
        assert q.get(5) == (5, 1, [2])

        q.touch((3, 1, [1]))
        q.push((7, 1, [3]))

        assert q.get(3) == (3, 1, [1])
        assert q.get(7) == (7, 1, [3])
        x = None
        try: x = q.get(5)
        except ValueError: pass
        assert x is None

        return True


class FileMap(object):
    """
    FileMap is a wrapper for a file-like object that satisfies the
      buffer interface. This is essentially the inverse of StringIO.
      It implements a caching layer over the calls to the OS seek/read
      functions for improved performance.

    Q: Why might you want this over mmap?
    A: 1) Its pure Python
       2) You can stack this over any Python file-like objects.
            eg. FileMap over ZipFile gives you a random access buffer
                  thats backed by a compressed image on the file system.
    """
    def __init__(self, filelike, block_size=MEGABYTE,
                 cache_size=10, size=None):
        """
        If `size` is not provided, then `filelike` must have the
          `seek` and `tell` methods implemented.
        """
        super(FileMap, self).__init__()
        if size is None:
            import os
            filelike.seek(0, os.SEEK_END)
            size = filelike.tell()
        self._f = filelike
        self._block_size = block_size
        self._size = size
        self._block_cache = RangeCache(cache_size)

    def __getitem__(self, index):
        if index < 0:
            index = self._size + index
        block_index = index % self._block_size
        block_start = index - block_index

        try:
            hit = self._block_cache.get(index)
            buf = hit[2]
            self._block_cache.touch(hit)
            return buf[block_index]
        except ValueError:
            self._f.seek(block_start)
            buf = self._f.read(self._block_size)
            self._block_cache.push((block_start, self._block_size, buf))
            return buf[block_index]

    def _get_containing_block(self, index):
        """
        Given an index, return block-aligned block that contains it,
          updating the appropriate caches.
        """
        block_index = index % self._block_size
        block_start = index - block_index

        try:
            hit = self._block_cache.get(block_start)
            buf = hit[2]
            self._block_cache.touch(hit)
            return buf
        except ValueError:
            self._f.seek(block_start)
            buf = self._f.read(self._block_size)
            self._block_cache.push((block_start, self._block_size, buf))
            return buf

    def __getslice__(self, start, end):
        if end == sys.maxint:
            end = self._size

        start_block_index = start % self._block_size
        start_block_start = start - start_block_index

        end_block_index = end % self._block_size
        end_block_start = end - end_block_index

        if start_block_start == end_block_start:
            # easy case, everything falls within the same block
            buf = self._get_containing_block(start)
            return buf[start_block_index:end_block_index]
        else:
            # hard case, slice goes over one or more block boundaries
            ret = ""

            # phase 1, start to block boundary
            buf = self._get_containing_block(start_block_start)
            s = start_block_index
            e = start_block_start + self._block_size
            ret += buf[s:e]

            # phase 2, any complete blocks
            cur_block_start = start_block_start + self._block_size
            while cur_block_start + self._block_size < end_block_start:
                buf = self._get_containing_block(cur_block_start)
                ret += buf
                cur_block_start += self._block_size

            # phase 3, block boundary to end
            buf = self._get_containing_block(cur_block_start)
            s = 0
            e = end_block_index or self._block_size
            ret += buf[0:e]
            return ret

    def __len__(self):
        return self._size

    @staticmethod
    def test():
        from cStringIO import StringIO
        f = StringIO("0123abcd4567efgh")
        buf = FileMap(f, block_size=4, cache_size=2)

        assert len(buf) == 16

        assert buf[0] == "0"
        assert buf[1] == "1"
        assert buf[0:2] == "01"

        assert buf[4] == "a"
        assert buf[5] == "b"
        assert buf[4:6] == "ab"

        assert buf[2:6] == "23ab"
        assert buf[0:8] == "0123abcd"

        assert buf[0:12] == "0123abcd4567"
        assert buf[0:16] == "0123abcd4567efgh"
        assert buf[:] == "0123abcd4567efgh"

        assert buf[-1] == "h"
        assert buf[-2:] == "gh"
        assert buf[-4:] == "efgh"
        assert buf[-8:] == "4567efgh"

        return True


def unpack_from(fmt, buffer, off=0):
    """
    Shim struct.unpack_from and divert unpacking of FileMaps.

    Otherwise, you'd get an exception like:
      TypeError: unpack_from() argument 1 must be convertible to a buffer, not FileMap

    So, we extract a true sub-buffer from the FileMap, and feed this
      back into the old unpack function.
    Theres an extra allocation and copy, but there's no getting
      around that.
    """
    if not isinstance(buffer, FileMap):
        return old_unpack_from(fmt, buffer, off)
    size = calcsize(fmt)
    buf = buffer[off:off + size]
    return old_unpack_from(fmt, buf, 0x0)


def unpack(fmt, string):
    """
    Like the shimmed unpack_from, but for struct.unpack.
    """
    if not isinstance(buffer, FileMap):
        return old_unpack(fmt, string)
    size = calcsize(fmt)
    buf = string[:size]
    return old_unpack(fmt, buf, 0x0)


def struct_test():
    from cStringIO import StringIO
    f = StringIO("\x04\x03\x02\x01")
    buf = FileMap(f)
    assert unpack_from("<B", buf, 0x0)[0] == 0x04
    assert unpack_from("<H", buf, 0x0)[0] == 0x0304
    assert unpack_from("<I", buf, 0x0)[0] == 0x01020304


def test():
    if LRUQueue.test():
        print "LRUQueue passed tests."
    if BoundedLRUQueue.test():
        print "BoundedLRUQueue passed tests."
    if RangeCache.test():
        print "RangeCache passed tests."
    if FileMap.test():
        print "FileMap passed tests."
    if struct_test():
        print "struct passed tests."


if __name__ == "__main__":
    test()

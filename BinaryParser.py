#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
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
#   Version v.0.1
import mmap
import struct
import sys
from datetime import datetime
import types
import cPickle

verbose = False


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


def debug(*message):
    global verbose
    if verbose:
        print "# [d] %s" % (", ".join(map(str, message)))


def warning(message):
    print "# [w] %s" % (message)


def info(message):
    print "# [i] %s" % (message)


def error(message):
    print "# [e] %s" % (message)
    sys.exit(-1)


def hex_dump(src, start_addr=0):
    """
    see:
    http://code.activestate.com/recipes/142812-hex-dumper/
    @param src A bytestring containing the data to dump.
    @param start_addr An integer representing the start
      address of the data in whatever context it comes from.
    @return A string containing a classic hex dump with 16
      bytes per line.  If start_addr is provided, then the
      data is interpreted as starting at this offset, and
      the offset column is updated accordingly.
    """
    FILTER = ''.join([(len(repr(chr(x))) == 3) and
                        chr(x) or
                        '.' for x in range(256)])
    length = 16
    result = []

    remainder_start_addr = start_addr

    if start_addr % length != 0:
        base_addr = start_addr - (start_addr % length)
        num_spaces = (start_addr % length)
        num_chars = length - (start_addr % length)

        spaces = " ".join(["  " for i in xrange(num_spaces)])
        s = src[0:num_chars]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        printable = s.translate(FILTER)

        result.append("%04X   %s %s   %s%s\n" %
                      (base_addr, spaces, hexa,
                      " " * (num_spaces + 1), printable))

        src = src[num_chars:]
        remainder_start_addr = base_addr + length

    for i in xrange(0, len(src), length):
        s = src[i:i + length]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append("%04X   %-*s   %s\n" %
                         (remainder_start_addr + i, length * 3,
                          hexa, printable))

    return ''.join(result)


class decoratorargs(object):
    def __new__(typ, *attr_args, **attr_kwargs):
        def decorator(orig_func):
            self = object.__new__(typ)
            self.__init__(orig_func, *attr_args, **attr_kwargs)
            return self
        return decorator


class memoize(decoratorargs):
    class Node:
        __slots__ = ['key', 'value', 'older', 'newer']

        def __init__(self, key, value, older=None, newer=None):
            self.key = key
            self.value = value
            self.older = older
            self.newer = newer

    def __init__(self, func, capacity=1000,
                 keyfunc=lambda *args, **kwargs: cPickle.dumps((args,
                                                                kwargs))):
        if not isinstance(func, property):
            self.func = func
            self.name = func.__name__
            self.is_property = False
        else:
            self.func = func.fget
            self.name = func.fget.__name__
            self.is_property = True
        self.capacity = capacity
        self.keyfunc = keyfunc
        self.reset()

    def reset(self):
        self.mru = self.Node(None, None)
        self.mru.older = self.mru.newer = self.mru
        self.nodes = {self.mru.key: self.mru}
        self.count = 1
        self.hits = 0
        self.misses = 0

    def __get__(self, inst, clas):
        self.obj = inst
        if self.is_property:
            return self.__call__()
        else:
            return self

    def __call__(self, *args, **kwargs):
        key = self.keyfunc(*args, **kwargs)
        try:
            node = self.nodes[key]
        except KeyError:
            # We have an entry not in the cache
            self.misses += 1
            func = types.MethodType(self.func, self.obj, self.name)
            value = func(*args, **kwargs)
            lru = self.mru.newer  # Always true
            # If we haven't reached capacity
            if self.count < self.capacity:
                # Put it between the MRU and LRU - it'll be the new MRU
                node = self.Node(key, value, self.mru, lru)
                self.mru.newer = node

                lru.older = node
                self.mru = node
                self.count += 1
            else:
                # It's FULL! We'll make the LRU be the new MRU, but replace its
                # value first
                try:
                    del self.nodes[lru.key]  # This mapping is now invalid
                except KeyError:  # HACK TODO: this may not work/leak
                    pass
                lru.key = key
                lru.value = value
                self.mru = lru

            # Add the new mapping
            self.nodes[key] = self.mru
            return value

        # We have an entry in the cache
        self.hits += 1

        # If it's already the MRU, do nothing
        if node is self.mru:
            return node.value

        lru = self.mru.newer  # Always true

        # If it's the LRU, update the MRU to be it
        if node is lru:
            self.mru = lru
            return node.value

        # Remove the node from the list
        node.older.newer = node.newer
        node.newer.older = node.older

        # Put it between MRU and LRU
        node.older = self.mru
        self.mru.newer = node

        node.newer = lru
        lru.older = node

        self.mru = node
        return node.value


def align(offset, alignment):
    """
    Return the offset aligned to the nearest greater given alignment
    Arguments:
    - `offset`: An integer
    - `alignment`: An integer
    """
    if offset % alignment == 0:
        return offset
    return offset + (alignment - (offset % alignment))


def dosdate(dosdate, dostime):
    """
    `dosdate`: 2 bytes, little endian.
    `dostime`: 2 bytes, little endian.
    returns: datetime.datetime or datetime.datetime.min on error
    """
    try:
        t  = ord(dosdate[1]) << 8
        t |= ord(dosdate[0])
        day   = t & 0b0000000000011111
        month = (t & 0b0000000111100000) >> 5
        year  = (t & 0b1111111000000000) >> 9
        year += 1980

        t  = ord(dostime[1]) << 8
        t |= ord(dostime[0])
        sec     = t & 0b0000000000011111
        sec    *= 2
        minute  = (t & 0b0000011111100000) >> 5
        hour    = (t & 0b1111100000000000) >> 11

        return datetime.datetime(year, month, day, hour, minute, sec)
    except:
        return datetime.datetime.min


def parse_filetime(qword):
    # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
    return datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)


class BinaryParserException(Exception):
    """
    Base Exception class for binary parsing.
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(BinaryParserException, self).__init__()
        self._value = value

    def __repr__(self):
        return "BinaryParserException(%r)" % (self._value)

    def __str__(self):
        return "Binary Parser Exception: %s" % (self._value)


class ParseException(BinaryParserException):
    """
    An exception to be thrown during binary parsing, such as
    when an invalid header is encountered.
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(ParseException, self).__init__(value)

    def __repr__(self):
        return "ParseException(%r)" % (self._value)

    def __str__(self):
        return "Parse Exception(%s)" % (self._value)


class OverrunBufferException(ParseException):
    def __init__(self, readOffs, bufLen):
        tvalue = "read: %s, buffer length: %s" % (hex(readOffs), hex(bufLen))
        super(ParseException, self).__init__(tvalue)

    def __repr__(self):
        return "OverrunBufferException(%r)" % (self._value)

    def __str__(self):
        return "Tried to parse beyond the end of the file (%s)" % \
            (self._value)


def read_byte(buf, offset):
    """
    Returns a little-endian unsigned byte from the relative offset of the given buffer.
    Arguments:
    - `buf`: The buffer from which to read the value.
    - `offset`: The relative offset from the start of the block.
    Throws:
    - `OverrunBufferException`
    """
    try:
        return struct.unpack_from("<B", buf, offset)[0]
    except struct.error:
        raise OverrunBufferException(offset, len(buf))


def read_word(buf, offset):
    """
    Returns a little-endian unsigned word from the relative offset of the given buffer.
    Arguments:
    - `buf`: The buffer from which to read the value.
    - `offset`: The relative offset from the start of the block.
    Throws:
    - `OverrunBufferException`
    """
    try:
        return struct.unpack_from("<H", buf, offset)[0]
    except struct.error:
        raise OverrunBufferException(offset, len(buf))


def read_dword(buf, offset):
    """
    Returns a little-endian unsigned dword from the relative offset of the given buffer.
    Arguments:
    - `buf`: The buffer from which to read the value.
    - `offset`: The relative offset from the start of the block.
    Throws:
    - `OverrunBufferException`
    """
    try:
        return struct.unpack_from("<I", buf, offset)[0]
    except struct.error:
        raise OverrunBufferException(offset, len(buf))


class Block(object):
    """
    Base class for structure blocks in binary parsing.
    A block is associated with a offset into a byte-string.
    """
    def __init__(self, buf, offset):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing stuff to parse.
        - `offset`: The offset into the buffer at which the block starts.
        """
        self._buf = buf
        self._offset = offset
        self._implicit_offset = 0
        # list of dict(offset:number, type:string, name:string,
        #              length:number, count:number)
        self._declared_fields = []

    def __repr__(self):
        return "Block(buf=%r, offset=%r)" % (self._buf, self._offset)

    def declare_field(self, type_, name, offset=None, length=None, count=None):
        """
        Declaratively add fields to this block.
        This method will dynamically add corresponding offset and
        unpacker methods to this block.

        Arguments:
        - `type_`: A string or a Nestable type.
            If a string, should be one of the unpack_* types.
            If a type, then it must be a subclass of Nestable.
        - `name`: A string.
        - `offset`: A number.
        - `length`: (Optional) A number. For (w)strings, length in chars.
        - `count`: (Optional) A number that specifies the number of
            instances of this type.
            If the count is greater than 1, then the handler will return
            a generator of the items. This parameter is not valid if
            the `length` parameter is provided.
        """
        is_generator = True
        if count is None:
            count = 1
            is_generator = False

        if count < 0:
            raise "Count must be greater than 0."

        if length is not None and count > 1:
            raise "Cannot specify both `length` and `count`."

        if offset is None:
            offset = self._implicit_offset

        basic_sizes = {
            "byte": 1,
            "int8": 1,
            "word": 2,
            "word_be": 2,
            "int16": 2,
            "dword": 4,
            "dword_be": 4,
            "int32": 4,
            "qword": 8,
            "int64": 8,
            "float": 4,
            "double": 8,
            "dosdate": 4,
            "filetime": 8,
            "systemtime": 8,
            "guid": 16,
        }

        handler = None

        if isinstance(type_, type):
            if not issubclass(type_, Nestable):
                raise TypeError("Invalid nested structure")

            typename = type_.__name__

            if count == 0:
                def no_class_handler():
                    return
                handler = no_class_handler
            elif is_generator:
                def many_class_handler():
                    ofs = offset
                    for _ in range(count):
                        r = type_(self._buf, self.absolute_offset(ofs), self)
                        ofs += len(r)
                        yield r
                handler = many_class_handler

                if hasattr(type_, "structure_size"):
                    ofs = offset
                    for _ in range(count):
                        ofs += type_.structure_size(self._buf, self.absolute_offset(ofs), self)
                    self._implicit_offset = ofs
                else:
                    ofs = offset
                    for _ in range(count):
                        r = type_(self._buf, self.absolute_offset(ofs), self)
                        ofs += len(r)
                    self._implicit_offset = ofs
            else:
                # TODO(wb): this needs to cache/memoize
                def class_handler():
                    return type_(self._buf, self.absolute_offset(offset), self)
                handler = class_handler

                if hasattr(type_, "structure_size"):
                    size = type_.structure_size(self._buf, self.absolute_offset(offset), self)
                    self._implicit_offset = offset + size
                else:
                    temp = type_(self._buf, self.absolute_offset(offset), self)

                    self._implicit_offset = offset + len(temp)
        elif isinstance(type_, basestring):
            typename = type_

            if count == 0:
                def no_basic_handler():
                    return
                handler = no_basic_handler
            elif is_generator:
                # length must be in basic_sizes
                def many_basic_handler():
                    ofs = offset
                    f = getattr(self, "unpack_" + type_)
                    for _ in range(count):
                        yield f(ofs)
                        ofs += basic_sizes[type_]
                handler = many_basic_handler

                self._implicit_offset = offset + count * basic_sizes[type_]
            else:
                if length is None:
                    def basic_no_length_handler():
                        f = getattr(self, "unpack_" + type_)
                        return f(offset)
                    handler = basic_no_length_handler

                    if type_ in basic_sizes:
                        self._implicit_offset = offset + basic_sizes[type_]
                    elif type_ == "binary":
                        self._implicit_offset = offset + length
                    elif type_ == "string" and length is not None:
                        self._implicit_offset = offset + length
                    elif type_ == "wstring" and length is not None:
                        self._implicit_offset = offset + (2 * length)
                    elif "string" in type_ and length is None:
                        raise ParseException("Implicit offset not supported for dynamic length strings")
                    else:
                        raise ParseException("Implicit offset not supported for type: " + type_)
                else:
                    def basic_length_handler():
                        f = getattr(self, "unpack_" + type_)
                        return f(offset, length)
                    handler = basic_length_handler

                    if type_ == "wstring":
                        self._implicit_offset = offset + (2 * length)
                    else:
                        self._implicit_offset = offset + length

        setattr(self, name, handler)
        setattr(self, "_off_" + name, offset)
        self.add_explicit_field(offset, typename, name, length, count)

        try:
            debug("(%s) %s\t@ %s\t: %s" % (typename.upper(),
                                           name,
                                           hex(self.absolute_offset(offset)),
                                           str(handler())[:0x20]))
        except ValueError: # invalid Windows timestamp
            debug("(%s) %s\t@ %s\t: %s" % (typename.upper(),
                                           name,
                                           hex(self.absolute_offset(offset)),
                                           "<<error>>"))

    def add_explicit_field(self, offset, typename, name, length=None, count=1):
        """
        The `Block` class tracks the fields that have been added so that you can
          pretty print the structure.  If there are other fields a subclass
          parses, use `add_explicit_field` to include them in the pretty printing.
        @type offset:  int
        @param offset: The offset at which the field begins.
        @type typename:  str or Block subclass
        @param typename: The type of the value of the field.
        @type name:  str
        @param name: The name of the field.
        @type length:  int
        @param length: An explicit length for the field.
        @type count:  int
        @param count: The number of repetitions for the field.
        @rtype: None
        @return: None
        """
        
        if type(typename) == type:
            typename = typename.__name__
        self._declared_fields.append({
                "offset": offset,
                "type": typename,
                "name": name,
                "length": length,
                "count": count,
                })

    def get_all_string(self, indent=0):
        """
        Get a nicely formatted, nested string of the contents of this structure
          and any sub-structures.  If a sub-structure has a method `.string()`, then
          this method will use it to represent its value.
          Implementation note, can't look for `__str__`, because everything has this.
        @type indent:  int
        @param indent: The level of nesting this objects has.
        @rtype: str
        @return A nicely formatted string that describes this structure.
        """
        ret = ""
        for field in self._declared_fields:
            v = getattr(self, field["name"])()
            if isinstance(v, Block):
                if hasattr(v, "string"):
                    ret += "%s%s (%s)%s\t%s\n" % \
                        ("  " * indent, hex(field["offset"]), field["type"], 
                         field["name"], v.string())
                else:
                    ret += "%s%s (%s)%s\n" % \
                        ("  " * indent, hex(field["offset"]), field["type"], 
                         field["name"])
                    ret += v.get_all_string(indent + 1)
            elif isinstance(v, types.GeneratorType):
                ret += "%s%s (%s *)%s\n" % ("  " * indent, hex(field["offset"]), field["type"], field["name"],)
                for i, j in enumerate(v):
                    ret += "%s[%d] (%s)\n" % ("  " * (indent + 1), i, field["type"])
                    ret += j.get_all_string(indent + 2)
            else:
                if isinstance(v, int):
                    v = hex(v)
                ret += "%s%s (%s)%s\t%s\n" % \
                    ("  " * indent, hex(field["offset"]), field["type"], 
                     field["name"],  str(v))
        return ret

    def current_field_offset(self):
        return self._implicit_offset

    def unpack_byte(self, offset):
        """
        Returns a little-endian unsigned byte from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        return read_byte(self._buf, self._offset + offset)

    def unpack_int8(self, offset):
        """
        Returns a little-endian signed byte from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<b", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_word(self, offset):
        """
        Returns a little-endian unsigned WORD (2 bytes) from the
          relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        return read_word(self._buf, self._offset + offset)

    def unpack_word_be(self, offset):
        """
        Returns a big-endian unsigned WORD (2 bytes) from the
          relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from(">H", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int16(self, offset):
        """
        Returns a little-endian signed WORD (2 bytes) from the
          relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<h", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def pack_word(self, offset, word):
        """
        Applies the little-endian WORD (2 bytes) to the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `word`: The data to apply.
        """
        o = self._offset + offset
        return struct.pack_into("<H", self._buf, o, word)

    def unpack_dword(self, offset):
        """
        Returns a little-endian DWORD (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        return read_dword(self._buf, self._offset + offset)

    def unpack_dword_be(self, offset):
        """
        Returns a big-endian DWORD (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from(">I", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int32(self, offset):
        """
        Returns a little-endian signed integer (4 bytes) from the
          relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<i", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_qword(self, offset):
        """
        Returns a little-endian QWORD (8 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<Q", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int64(self, offset):
        """
        Returns a little-endian signed 64-bit integer (8 bytes) from
          the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<q", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_float(self, offset):
        """
        Returns a single-precision float (4 bytes) from
          the relative offset.  IEEE 754 format.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<f", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_double(self, offset):
        """
        Returns a double-precision float (8 bytes) from
          the relative offset.  IEEE 754 format.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<d", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_binary(self, offset, length=False):
        """
        Returns raw binary data from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the binary blob. If zero, the empty string
            zero length is returned.
        Throws:
        - `OverrunBufferException`
        """
        if not length:
            return ""
        o = self._offset + offset
        try:
            return struct.unpack_from("<%ds" % (length), self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_string(self, offset, length):
        """
        Returns a string from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the string.
        Throws:
        - `OverrunBufferException`
        """
        return self.unpack_binary(offset, length)

    def unpack_wstring(self, offset, length):
        """
        Returns a string from the relative offset with the given length,
        where each character is a wchar (2 bytes)
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the string.
        Throws:
        - `UnicodeDecodeError`
        """
        try:
            return self._buf[self._offset + offset:self._offset + offset + \
                             2 * length].tostring().decode("utf16")
        except AttributeError: # already a 'str' ?
            return self._buf[self._offset + offset:self._offset + offset + \
                             2 * length].decode("utf16")

    def unpack_dosdate(self, offset):
        """
        Returns a datetime from the DOSDATE and DOSTIME starting at
        the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        try:
            o = self._offset + offset
            return dosdate(self._buf[o:o + 2], self._buf[o + 2:o + 4])
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_filetime(self, offset):
        """
        Returns a datetime from the QWORD Windows timestamp starting at
        the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        return parse_filetime(self.unpack_qword(offset))

    def unpack_systemtime(self, offset):
        """
        Returns a datetime from the QWORD Windows SYSTEMTIME timestamp
          starting at the relative offset.
          See http://msdn.microsoft.com/en-us/library/ms724950%28VS.85%29.aspx
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            parts = struct.unpack_from("<WWWWWWWW", self._buf, o)
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))
        return datetime.datetime(parts[0], parts[1],
                                 parts[3],  # skip part 2 (day of week)
                                 parts[4], parts[5],
                                 parts[6], parts[7])

    def unpack_guid(self, offset):
        """
        Returns a string containing a GUID starting at the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset

        try:
            _bin = self._buf[o:o + 16]
        except IndexError:
            raise OverrunBufferException(o, len(self._buf))

        # Yeah, this is ugly
        h = map(ord, _bin)
        return "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x" % \
            (h[3], h[2], h[1], h[0],
             h[5], h[4],
             h[7], h[6],
             h[8], h[9],
             h[10], h[11], h[12], h[13], h[14], h[15])

    def absolute_offset(self, offset):
        """
        Get the absolute offset from an offset relative to this block
        Arguments:
        - `offset`: The relative offset into this block.
        """
        return self._offset + offset

    def offset(self):
        """
        Equivalent to self.absolute_offset(0x0), which is the starting
          offset of this block.
        """
        return self._offset


class Nestable(object):
    """
    A Nestable is a mixin type that can be provided with a Block type.
    The only requirement is that it implement a `len` method, or a
    `structure_size` staticmethod.  This enables the parent Block to
    seek among its children.
    """
    def __init__(self, buf, offset):
        super(Nestable, self).__init__()

    @staticmethod
    def structure_size(buf, offset, parent):
        """
        This staticmethod should return the size of a block located at the
          specified location in the given buffer.  This method should do the
          minimal amount of processing involved to compute the size.  It should
          not perform any worse than simply instantiating the this type and
          using its `__len__` method.

        @type  buf: bytestring
        @param buf: The buffer in which this Block is found.
        @type  offset: int
        @param offset: The offset at which this Block begins.
        @type  parent: object
        @param parent: The logical parent of this Block.
        @rtype: int
        @return The length of the Block starting at the given location.
        """
        raise NotImplemented

    def __len__(self):
        """
        This method should return the size of this structure in bytes.
        It should prefer to use size fields or logic that
          is already parsed out.

        @rtype: int
        @return The length of this Block in bytes.
        """
        raise NotImplemented

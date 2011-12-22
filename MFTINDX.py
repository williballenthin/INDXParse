#!/bin/python

#    This file is part of INDXParse.
#
#   Copyright 2011 Will Ballenthin <william.ballenthin@mandiant.com>
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

import struct, time, array, sys, cPickle
from datetime import datetime

import argparse
global verbose

def debug(message):
    global verbose
    if verbose:
        print "# [d] %s" % (message)

def warning(message):
    print "# [w] %s" % (message)

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
            
    def __init__(self, func, capacity, 
                 keyfunc=lambda *args, **kwargs: cPickle.dumps((args, kwargs))):
        self.func = func
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
        
    def __call__(self, *args, **kwargs):
        key = self.keyfunc(*args, **kwargs)
        try:
            node = self.nodes[key]
        except KeyError:
            # We have an entry not in the cache
            self.misses += 1
            value = self.func(*args, **kwargs)
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
                del self.nodes[lru.key]  # This mapping is now invalid
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

def parse_windows_timestamp(qword):
    # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
    return datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)

class INDXException(Exception):
    """
    Base Exception class for INDX parsing.
    """    
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(INDXException, self).__init__()
        self._value = value

    def __str__(self):
        return "INDX Exception: %s" % (self._value)

class ParseException(INDXException):
    """
    An exception to be thrown during NTFS INDX parsing, such as 
    when an invalid header is encountered.
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(ParseException, self).__init__(value)

    def __str__(self):
        return "INDX Parse Exception(%s)" % (self._value)

class OverrunBufferException(ParseException):
    def __init__(self, readOffs, bufLen):
        tvalue = "read: %s, buffer length: %s" % (hex(readOffs), hex(bufLen))
        super(ParseException, self).__init__(tvalue)

    def __str__(self):
        return "Tried to parse beyond the end of the file (%s)" % (self._value)

class Block(object):
    """ 
    Base class for structure blocks in the NTFS INDX format.
    A block is associated with a offset into a byte-string.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        self._buf = buf
        self._offset = offset
        self._parent = parent
        self._implicit_offset = 0

    def __unicode__(self):
        return u"BLOCK @ %s." % (hex(self.offset()))

    def __str__(self):
        return str(unicode(self))

    def declare_field(self, type, name, offset=False, length=False):
        """
        Declaratively add fields to this block.
        This method will dynamically add corresponding offset and unpacker methods
        to this block.
        Arguments:
        - `type`: A string. Should be one of the unpack_* types.
        - `name`: A string. 
        - `offset`: A number.
        - `length`: (Optional) A number.
        """
        if not offset:
            offset = self._implicit_offset
            def handler():
                f = getattr(self, "unpack_" + type)
                return f(offset)
        elif not length:
            def handler():
                f = getattr(self, "unpack_" + type)
                return f(offset)
        else:
            def handler():
                f = getattr(self, "unpack_" + type)
                return f(offset, length)

        setattr(self, name, handler)
        setattr(self, "_off_" + name, offset)
        debug("(%s) %s\t@ %s\t: %s" % (type.upper(), 
                                       name, 
                                       hex(self.absolute_offset(offset)),
                                       str(handler())[:0x20]))

        if type == "byte":
            self._implicit_offset = offset + 1
        elif type == "word":
            self._implicit_offset = offset + 2
        elif type == "dword":
            self._implicit_offset = offset + 4
        elif type == "qword":
            self._implicit_offset = offset + 8
        elif type == "int":
            self._implicit_offset = offset + 4
        elif type == "dosdate":
            self._implicit_offset = offset + 4
        elif type == "windows_timestamp":
            self._implicit_offset = offset + 8
        elif type == "binary":
            self._implicit_offset = offset + length
        elif type == "string" and length:
            self._implicit_offset = offset + length
        elif type == "wstring" and length:
            self._implicit_offset = offset + (2 * length)
        elif "string" in type and not length:
            raise INDXException("Implicit offset not supported for dynamic length strings")
        else:
            raise INDXException("Implicit offset not supported for type: " + type)            

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
        o = self._offset + offset
        try:
            return struct.unpack_from("<B", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_word(self, offset):
        """
        Returns a little-endian WORD (2 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<H", self._buf, o)[0]
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
        o = self._offset + offset
        try:
            return struct.unpack_from("<I", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int(self, offset):
        """
        Returns a little-endian signed integer (4 bytes) from the relative offset.
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

    def unpack_windows_timestamp(self, offset):
        """
        Returns a datetime from the QWORD Windows timestamp starting at
        the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        return parse_windows_timestamp(self.unpack_qword(offset))

    def absolute_offset(self, offset):
        """
        Get the absolute offset from an offset relative to this block
        Arguments:
        - `offset`: The relative offset into this block.
        """
        return self._offset + offset

    def parent(self):
        """
        Get the parent block. See the class documentation for what the parent link is.
        """
        return self._parent

    def offset(self):
        """
        Equivalent to self.absolute_offset(0x0), which is the starting offset of this block.
        """
        return self._offset

class FixupBlock(Block):
    def __init__(self, buf, offset, parent):
        super(FixupBlock, self).__init__(buf, offset, parent)

    def fixup(self, num_fixups, fixup_value_offset):
        fixup_value = self.unpack_word(fixup_value_offset)
    
        for i in range(0, num_fixups - 1):
            fixup_offset = 512 * (i + 1) - 2
            check_value = self.unpack_word(fixup_offset)
        
            if check_value != fixup_value:
                warning("Bad fixup at %s" % (hex(self.offset() + fixup_offset)))
                continue

            new_value = self.unpack_word(fixup_value_offset + 2 + 2 * i)
            self.pack_word(fixup_offset, new_value)
        
            check_value = self.unpack_word(fixup_offset)
            debug("Fixup verified at %s and patched from %s to %s." % \
                  (hex(self.offset() + fixup_offset),
                   hex(fixup_value), hex(check_value)))

class IndexRootHeader(Block):
    def __init__(self, buf, offset, parent):
        debug("INDEX ROOT HEADER at %s." % (hex(offset)))
        super(IndexRootHeader, self).__init__(buf, offset, parent)
        self.declare_field("dword", "type", 0x0)
        self.declare_field("dword", "collation_rule")
        self.declare_field("dword", "index_record_size_bytes")
        self.declare_field("byte",  "index_record_size_clusters")
        self.declare_field("byte", "unused1")
        self.declare_field("byte", "unused2")
        self.declare_field("byte", "unused3")
        self._node_header_offset = self.current_field_offset()
    
    def node_header(self):
        return IndexNodeHeader(self._buf, self.offset() + self._node_header_offset, self)

class IndexNodeHeader(Block):
    def __init__(self, buf, offset, parent):
        debug("INDEX NODE HEADER at %s." % (hex(offset)))
        super(IndexNodeHeader, self).__init__(buf, offset, parent)
        self.declare_field("dword", "entry_list_start", 0x0)
        self.declare_field("dword", "entry_list_end")
        self.declare_field("dword", "entry_list_allocation_end")
        self.declare_field("dword", "flags")
        self.declare_field("binary", "list_buffer", \
                           self.entry_list_start(), 
                           self.entry_list_allocation_end() - self.entry_list_start())

    def entries(self):
        """
        A generator that returns each INDX entry associated with this node.
        """
        offset = self.entry_list_start()
        if offset == 0:
            debug("No entries in this allocation block.")
            return 
        while offset <= self.entry_list_end() - self.offset() - 0x52:
            debug("Entry has another entry after it.")
            e = IndexEntry(self._buf, self.offset() + offset, self)
            offset += e.length()
            yield e
        debug("No more entries.")

    def slack_entries(self):
        """
        A generator that yields INDX entries found in the slack space
        associated with this header.
        """
        offset = self.entry_list_end()
        try:
            while offset <= self.entry_list_allocation_end() - self.offset() - 0x52:
                try:
                    debug("Trying to find slack entry at %s." % (hex(offset)))
                    e = SlackIndexEntry(self._buf, offset, self)
                    if e.is_valid():
                        debug("Slack entry is valid.")
                        offset += e.length()
                        yield e
                    else:
                        debug("Slack entry is invalid.")
                        raise ParseException("Not a deleted entry")
                except ParseException:
                    debug("Scanning one byte forward.")
                    offset += 1
        except struct.error:
            debug("Slack entry parsing overran buffer.")
            pass

class IndexEntry(Block):
    def __init__(self, buf, offset, parent):
        debug("INDEX ENTRY at %s." % (hex(offset)))
        super(IndexEntry, self).__init__(buf, offset, parent)
        self.declare_field("qword", "mft_reference", 0x0)
        self.declare_field("word", "length")
        self.declare_field("word", "filename_information_length")
        self.declare_field("dword", "flags")
        if self.filename_information_length() > 0:
            self.declare_field("binary", "filename_information_buffer", \
                               self.current_field_offset(), self.filename_information_length())
        self.declare_field("qword", "child_vcn", align(self.current_field_offset(), 0x8))

    def filename_information(self):
        return FilenameAttribute(self._buf, 
                                 self.offset() + self._off_filename_information_buffer, 
                                 self)

class StandardInformation(Block):
    def __init__(self, buf, offset, parent):
        debug("STANDARD INFORMATION ATTRIBUTE at %s." % (hex(offset)))
        super(StandardInformation, self).__init__(buf, offset, parent)
        self.declare_field("windows_timestamp", "created_time", 0x0)
        self.declare_field("windows_timestamp", "modified_time")
        self.declare_field("windows_timestamp", "changed_time")
        self.declare_field("windows_timestamp", "accessed_time")
        self.declare_field("dword", "attributes")
        self.declare_field("binary", "reserved", self.current_field_offset(), 12)
        # there may be more after this if its a new NTFS

class FilenameAttribute(Block):
    def __init__(self, buf, offset, parent):
        debug("FILENAME ATTRIBUTE at %s." % (hex(offset)))
        super(FilenameAttribute, self).__init__(buf, offset, parent)
        self.declare_field("qword", "mft_parent_reference", 0x0)
        self.declare_field("windows_timestamp", "created_time")
        self.declare_field("windows_timestamp", "modified_time")
        self.declare_field("windows_timestamp", "changed_time")
        self.declare_field("windows_timestamp", "accessed_time")
        self.declare_field("qword", "physical_size")
        self.declare_field("qword", "logical_size")
        self.declare_field("dword", "flags")
        self.declare_field("dword", "reparse_value")
        self.declare_field("byte", "filename_length")
        self.declare_field("byte", "filename_type")
        self.declare_field("wstring", "filename", 0x42, self.filename_length())

        if self.filename_type() > 4:
            warning("Invalid INDX record entry filename type at 0x%s" % \
                    (hex(self.offset() + self._filename_type_offset)))
    
class SlackIndexEntry(IndexEntry):
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent NTATTR_STANDARD_INDEX_HEADER block, which links to this block.
        """
        super(SlackIndexEntry, self).__init__(buf, offset, parent)

    def is_valid(self):
        recent_date = datetime(1990, 1, 1, 0, 0, 0)
        return self.modified_time_safe() > recent_date and \
            self.accessed_time_safe() > recent_date and \
            self.changed_time_safe() > recent_date and \
            self.created_time_safe() > recent_date

class ATTR_TYPE:
    STANDARD_INFORMATION = 0x10
    FILENAME_INFORMATION = 0x30
    DATA = 0x80
    INDEX_ROOT = 0x90
    INDEX_ALLOCATION = 0xA0

class Attribute(Block):
    def __init__(self, buf, offset, parent):
        super(Attribute, self).__init__(buf, offset, parent)
        debug("ATTRIBUTE @ %s." % (hex(offset)))
        self.declare_field("dword", "type")
        self.declare_field("dword", "size")
        self.declare_field("byte", "non_resident")
        self.declare_field("byte", "name_length")
        self.declare_field("word", "name_offset")
        self.declare_field("word", "flags")
        self.declare_field("word", "instance")
        if self.non_resident() > 0:
            self.declare_field("qword", "lowest_vcn", 0x10)
            self.declare_field("qword", "highest_vcn")
            self.declare_field("word", "runlist_offset")
            self.declare_field("byte", "compression_unit")
            self.declare_field("byte", "reserved1")
            self.declare_field("byte", "reserved2")
            self.declare_field("byte", "reserved3")
            self.declare_field("byte", "reserved4")
            self.declare_field("byte", "reserved5")
            self.declare_field("qword", "allocated_size")
            self.declare_field("qword", "data_size")
            self.declare_field("qword", "initialized_size")
            self.declare_field("qword", "compressed_size")
        else:
            self.declare_field("dword", "value_length", 0x10)
            self.declare_field("word", "value_offset")
            self.declare_field("byte", "value_flags")
            self.declare_field("byte", "reserved")
            self.declare_field("binary", "value", self.value_offset(), self.value_length())
            
    def runlist(self):
        return Runlist(buf, self.runlist_offset(), self)

    def size(self):
        s = self.unpack_dword(self._size_offset) 
        return s + (8 - (s % 8))

class MFTRecord(FixupBlock):
    def __init__(self, buf, offset, parent):
        super(MFTRecord, self).__init__(buf, offset, parent)
        debug("MFTRECORD @ %s." % (hex(offset)))
        self.declare_field("dword", "magic")
        self.declare_field("word",  "usa_offset")
        self.declare_field("word",  "usa_count")
        self.declare_field("qword", "lsn")
        self.declare_field("word",  "sequence_number")
        self.declare_field("word",  "link_count")
        self.declare_field("word",  "attrs_offset")
        self.declare_field("word",  "flags")
        self.declare_field("dword", "bytes_in_use")
        self.declare_field("dword", "bytes_allocated")
        self.declare_field("qword", "base_mft_record")
        self.declare_field("word",  "next_attr_instance")
        self.declare_field("word",  "reserved")
        self.declare_field("dword", "mft_record_number")

        self.fixup(self.usa_count(), self.usa_offset())

    def attributes(self):
        offset = self.attrs_offset()
        while self.unpack_dword(offset) != 0 and self.unpack_dword(offset) != 0xFFFFFFFF:
            a = Attribute(self._buf, offset, self)
            offset += a.size()
            yield a

    def attribute(self, attr_type):
        for a in self.attributes():
            if a.type() == attr_type:
                return a

    def is_directory(self):
        return self.flags() & 0x0002

    def is_active(self):
        return self.flags() & 0x0001

    # this a required resident attribute
    def filename_information(self):
        """
        MFT Records may have more than one FN info attribute, 
        each with a different type of filename (8.3, POSIX, etc.)
        This one tends towards WIN32.
        """
        fn = False
        for a in self.attributes():
            if a.type() == ATTR_TYPE.FILENAME_INFORMATION: # TODO optimize to self._buf here
                try:
                    value = a.value()
                    check = FilenameAttribute(value, 0, self)
                    if check.filename_type() == 0x0001 or \
                       check.filename_type() == 0x0003:
                        return check
                    fn = check
                except:
                    pass
        return fn

    # this a required resident attribute
    def standard_information(self):
        try:
            attr = self.attribute(ATTR_TYPE.STANDARD_INFORMATION)
            return StandardInformation(attr.value(), 0, self)
        except:
            return False

def record_generator(filename):
    with open(filename, "rb") as f:
        record = f.read(1024)
        while record:
            yield record
            buf = array.array("B", f.read(1024))
            if not buf:
                return
            record = MFTRecord(buf, 0, False)

@memoize(100)
def mft_get_record_buf(filename, number):
    with open(filename, "rb") as f:
        f.seek(number * 1024)
        return array.array("B", f.read(1024))

# This would be a local function to record_build_path,
# but we can't pickle a local function, and 
# memoization is key here.
# TODO merge this back into record_build_path
@memoize(100)
def _record_build_path_rec(mftfilename, parent_ref):
    if parent_ref & 0xFFFFFFFFFFFF == 0x0005:
        return "\\."
    parent_buf = mft_get_record_buf(mftfilename, parent_ref & 0xFFFFFFFFFFFF)
    if parent_buf == "":
        return "\\??"
    parent = MFTRecord(parent_buf, 0, False)
    if parent.sequence_number() != parent_ref >> 48:
        return "\\$OrphanFiles"
    pfn = parent.filename_information()
    if not pfn:
        return "\\??"
    return _record_build_path_rec(mftfilename, pfn.mft_parent_reference()) + "\\" + pfn.filename()

def record_build_path(mftfilename, record):
    fn = record.filename_information()
    if not fn:
        return "??"
    return _record_build_path_rec(mftfilename, fn.mft_parent_reference()) + "\\" + fn.filename()

class InvalidAttributeException(INDXException):
    def __init__(self, value):
        super(InvalidAttributeException, self).__init__(value)

    def __str__(self):
        return "Invalid attribute Exception(%s)" % (self._value)

def record_bodyfile(filename, record, attributes=[]):
    path = record_build_path(filename, record)
    si = record.standard_information()
    if not si:
        raise InvalidAttributeException("Unable to parse attribute")
    fn = record.filename_information()
    if not fn:
        raise InvalidAttributeException("Unable to parse attribute")
    try:
        si_modified = int(time.mktime(si.modified_time().timetuple()))    
    except ValueError:
        si_modified = int(time.mktime(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        si_accessed = int(time.mktime(si.accessed_time().timetuple()))
    except ValueError:
        si_accessed = int(time.mktime(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        si_changed  = int(time.mktime(si.changed_time().timetuple()))
    except ValueError:
        si_changed = int(time.mktime(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        si_created  = int(time.mktime(si.created_time().timetuple()))
    except ValueError:
        si_created = int(time.mktime(datetime.min.timetuple()))
    attributes_text = ""
    if len(attributes) > 0:
        attributes_text = " (%s)" % (", ".join(attributes))
    si_half = u"0|%s|%s|0|0|0|%s|%s|%s|%s|%s" % (path + attributes_text, \
                                                 record.mft_record_number(), \
                                                 fn.logical_size(), si_modified, 
                                                 si_accessed, si_changed, si_created)
    try:
        fn_modified = int(time.mktime(fn.modified_time().timetuple()))    
    except ValueError:
        fn_modified = int(time.mktime(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        fn_accessed = int(time.mktime(fn.accessed_time().timetuple()))
    except ValueError:
        fn_accessed = int(time.mktime(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        fn_changed  = int(time.mktime(fn.changed_time().timetuple()))
    except ValueError:
        fn_changed = int(time.mktime(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        fn_created  = int(time.mktime(fn.created_time().timetuple()))
    except ValueError:
        fn_created = int(time.mktime(datetime.min.timetuple()))
    attributes_text = " (filename)"
    if len(attributes) > 0:
        attributes_text = " (filename, %s)" % (", ".join(attributes))
    fn_half = u"0|%s|%s|0|0|0|%s|%s|%s|%s|%s" % (path + attributes_text, \
                                                 record.mft_record_number(), \
                                                 fn.logical_size(), \
                                                 fn_modified, fn_accessed, \
                                                 fn_changed, fn_created)
    return "%s\n%s" % (si_half, fn_half)

def doit(filename, directory):
    count = 0
    for record in record_generator(filename):
        count += 1
        if count < 16:
            continue
        # TODO check signature
        try:
            if record.is_active():
                print record_bodyfile(filename, record)                
            else:
                print record_bodyfile(filename, record, ["deleted"])                
        except InvalidAttributeException:
            pass

if __name__ == '__main__':
    global verbose
    verbose = False

    doit(sys.argv[1], sys.argv[2])

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
#
#   Version v.1.1.8

import struct, time, array, sys, cPickle, re, os, calendar
from datetime import datetime
import types

verbose = False

def debug(message):
    global verbose
    if verbose:
        print "# [d] %s" % (message)

def warning(message):
    print "# [w] %s" % (message)

def info(message):
    print "# [i] %s" % (message)

def error(message):
    print "# [e] %s" % (message)
    sys.exit(-1)

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
 #           try:
            func = types.MethodType(self.func, self.obj, self.name)
            value = func(*args, **kwargs)
#            except:
#                value = self.func(*args, **kwargs)                
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
                except KeyError: # HACK TODO: this may not work/leak
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

    def declare_field(self, type, name, offset=None, length=None):
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
        if offset == None:
            offset = self._implicit_offset
            def handler():
                f = getattr(self, "unpack_" + type)
                return f(offset)
        elif length == None:
            def handler():
                f = getattr(self, "unpack_" + type)
                return f(offset)
        else:
            def handler():
                f = getattr(self, "unpack_" + type)
                return f(offset, length)

        setattr(self, name, handler)
        setattr(self, "_off_" + name, offset)
        try:
            debug("(%s) %s\t@ %s\t: %s" % (type.upper(), 
                                           name, 
                                           hex(self.absolute_offset(offset)),
                                           str(handler())[:0x20]))
        except ValueError: # invalid Windows timestamp
            debug("(%s) %s\t@ %s\t: %s" % (type.upper(), 
                                           name, 
                                           hex(self.absolute_offset(offset)),
                                           "<<error>>"))
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
        elif type == "string" and length != None:
            self._implicit_offset = offset + length
        elif type == "wstring" and length != None:
            self._implicit_offset = offset + (2 * length)
        elif "string" in type and length == None:
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

class IndexRecordHeader(FixupBlock):
    def __init__(self, buf, offset, parent):
        debug("INDEX RECORD HEADER at %s." % (hex(offset)))
        super(IndexRecordHeader, self).__init__(buf, offset, parent)
        self.declare_field("dword", "magic", 0x0)
        self.declare_field("word",  "usa_offset")
        self.declare_field("word",  "usa_count")
        self.declare_field("qword", "lsn")
        self.declare_field("qword", "vcn")
        self._node_header_offset = self.current_field_offset()
        self.fixup(self.usa_count(), self.usa_offset())
        
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
        while offset <= self.entry_list_end() - 0x52:
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
            while offset <= self.entry_list_allocation_end() - 0x52:
                try:
                    debug("Trying to find slack entry at %s." % (hex(offset)))
                    e = SlackIndexEntry(self._buf, offset, self)
                    if e.is_valid():
                        debug("Slack entry is valid.")
                        offset += e.length() or 1
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
        # this is a bit of a mess, but it should work
        recent_date = datetime(1990, 1, 1, 0, 0, 0)
        future_date = datetime(2025, 1, 1, 0, 0, 0)
        try:
            fn = self.filename_information()
        except:
            return False
        if not fn:
            return False
        try:
            return fn.modified_time() > recent_date and \
                   fn.accessed_time() > recent_date and \
                   fn.changed_time() > recent_date and \
                   fn.created_time() > recent_date and \
                   fn.modified_time() < future_date and \
                   fn.accessed_time() < future_date and \
                   fn.changed_time() < future_date and \
                   fn.created_time() < future_date
        except ValueError:
            return False

class Runentry(Block):
    def __init__(self, buf, offset, parent):
        super(Runentry, self).__init__(buf, offset, parent)
        debug("RUNENTRY @ %s." % (hex(offset)))
        self.declare_field("byte", "header")
        self._offset_length = self.header() >> 4
        self._length_length = self.header() & 0xF
        self.declare_field("binary", "length_binary", self.current_field_offset(), self._length_length)
        self.declare_field("binary", "offset_binary", self.current_field_offset(), self._offset_length)

    def is_valid(self):
        return self._offset_length > 0 and self._length_length > 0

    def lsb2num(self, binary):
        count = 0
        ret = 0
        for b in binary:
            ret += ord(b) << (8 * count)
            count += 1
        return ret

    def lsb2signednum(self, binary):
        count = 0
        ret = 0
        working = []

        is_negative = (ord(binary[-1]) & (1 << 7) != 0)
        if is_negative:
            working = [ord(b) ^ 0xFF for b in binary]
        else:
            working = [ord(b) for b in binary]
        for b in working:
            ret += b << (8 * count)
            count += 1
        if is_negative:
            ret += 1
            ret *= -1
        return ret

    def offset(self):
        return self.lsb2signednum(self.offset_binary())

    def length(self):
        return self.lsb2num(self.length_binary())

    def size(self):
        return self.current_field_offset()

class Runlist(Block):
    def __init__(self, buf, offset, parent):
        super(Runlist, self).__init__(buf, offset, parent)
        debug("RUNLIST @ %s." % (hex(offset)))

    def _entries(self, length=None):
        ret = []
        offset = self.offset()
        entry = Runentry(self._buf, offset, self)
        while entry.header() != 0 and \
              (not length or offset < self.offset() + length) and \
              entry.is_valid():
            ret.append(entry)
            offset += entry.size()
            entry = Runentry(self._buf, offset, self)
        return ret

    def runs(self, length=None):
        """
        Yields tuples (volume offset, length).
        Recall that the entries are relative to one another
        """
        last_offset = 0
        for e in self._entries(length=length):
            current_offset = last_offset + e.offset()
            current_length = e.length()
            last_offset = current_offset
            yield (current_offset, current_length)

class ATTR_TYPE:
    STANDARD_INFORMATION = 0x10
    FILENAME_INFORMATION = 0x30
    DATA = 0x80
    INDEX_ROOT = 0x90
    INDEX_ALLOCATION = 0xA0

class Attribute(Block):
    TYPES = {
      16: "$STANDARD INFORMATION",
      32: "$ATTRIBUTE LIST",
      48: "$FILENAME INFORMATION",
      64: "$OBJECT ID/$VOLUME VERSION",
      80: "$SECURITY DESCRIPTOR",
      96: "$VOLUME NAME",
      112: "$VOLUME INFORMATION",
      128: "$DATA",
      144: "$INDEX ROOT",
      160: "$INDEX ALLOCATION",
      176: "$BITMAP",
      192: "$SYMBOLIC LINK",
      208: "$REPARSE POINT/$EA INFORMATION",
      224: "$EA",
      256: "$LOGGED UTILITY STREAM"
    }

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
        return Runlist(self._buf, self.offset() + self.runlist_offset(), self)

    def size(self):
        s = self.unpack_dword(self._off_size) 
        return s + (8 - (s % 8))

    def name(self):
        return self.unpack_wstring(self.name_offset(), self.name_length())

class MFTRecord(FixupBlock):
    def __init__(self, buf, offset, parent, inode=None):
        super(MFTRecord, self).__init__(buf, offset, parent)
        debug("MFTRECORD @ %s." % (hex(offset)))
        self.inode = inode or 0
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

        while self.unpack_dword(offset) != 0 and \
              self.unpack_dword(offset) != 0xFFFFFFFF and \
              offset + self.unpack_dword(offset + 4) <= self.offset() + self.bytes_in_use():
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
        # TODO what about link count == 0?
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
                except Exception as e:
                    pass
        return fn

    # this a required resident attribute
    def standard_information(self):
        try:
            attr = self.attribute(ATTR_TYPE.STANDARD_INFORMATION)
            return StandardInformation(attr.value(), 0, self)
        except AttributeError:
            return False

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

class InvalidMFTRecordNumber(Exception):
    def __init__(self, value):
        self.value = value

class NTFSFile():
    def __init__(self, options):
        if type(options) == dict:
            self.filename  = options["filename"]
            self.filetype  = options["filetype"] or "mft"
            self.offset    = options["offset"] or 0
            self.clustersize = options["clustersize"] or 4096
            self.mftoffset = False
            self.prefix    = options["prefix"] or None
            self.progress  = options["progress"]
        else:
            self.filename  = options.filename
            self.filetype  = options.filetype
            self.offset    = options.offset
            self.clustersize = options.clustersize
            self.mftoffset = False
            self.prefix    = options.prefix
            self.progress  = options.progress

    # TODO calculate cluster size

    def _calculate_mftoffset(self):
        with open(self.filename, "rb") as f:
            f.seek(self.offset)
            f.seek(0x30, 1) # relative
            buf = f.read(8)
            relmftoffset = struct.unpack_from("<Q", buf, 0)[0]
            self.mftoffset = self.offset + relmftoffset * self.clustersize
            debug("MFT offset is %s" % (hex(self.mftoffset)))

    def record_generator(self):
        if self.filetype == "indx":
            return
        if self.filetype == "mft":
            size = os.path.getsize(self.filename)
            is_redirected = os.fstat(0) != os.fstat(1)
            should_progress = is_redirected and self.progress
            with open(self.filename, "rb") as f:
                record = True
                count = -1
                while record:
                    if count % 100 == 0 and should_progress: 
                        n = (count * 1024 * 100) / float(size)
                        sys.stderr.write("\rCompleted: %0.4f%%" % (n))
                        sys.stderr.flush()
                    count += 1
                    buf = array.array("B", f.read(1024))
                    if not buf:
                        return
                    try:
                        record = MFTRecord(buf, 0, False, inode=count)
                    except OverrunBufferException:
                        debug("Failed to parse MFT record %s" % (str(count)))
                        continue
                    debug("Yielding record " + str(count))
                    yield record
            if should_progress:
                sys.stderr.write("\n")
        if self.filetype == "image":
            # TODO this overruns the MFT...
            # TODO this doesnt account for a fragmented MFT
            with open(self.filename, "rb") as f:
                if not self.mftoffset:
                    self._calculate_mftoffset()
                f.seek(self.mftoffset)
                record = True
                count = -1
                while record:
                    count += 1
                    buf = array.array("B", f.read(1024))
                    if not buf:
                        return
                    try:
                        record = MFTRecord(buf, 0, False, inode=count)
                    except OverrunBufferException:
                        debug("Failed to parse MFT record %s" % (str(count)))
                        continue
                    debug("Yielding record " + str(count))
                    yield record
            
    def mft_get_record_buf(self, number):
        if self.filetype == "indx":
            return array.array("B", "")
        if self.filetype == "mft":
            with open(self.filename, "rb") as f:
                f.seek(number * 1024)
                return array.array("B", f.read(1024))
        if self.filetype == "image":
            with open(self.filename, "rb") as f:
                f.seek(number * 1024)
                if not self.mftoffset:
                    self._calculate_mftoffset()
                f.seek(self.mftoffset)
                f.seek(number * 1024, 1)
                return array.array("B", f.read(1024))

    def mft_get_record(self, number):
        buf = self.mft_get_record_buf(number)
        if buf == array.array("B", ""):
            raise InvalidMFTRecordNumber(number)
        return MFTRecord(buf, 0, False)

    # memoization is key here.
    @memoize(100, keyfunc=lambda r, _: 
             str(r.magic()) + str(r.lsn()) + str(r.link_count()) + \
             str(r.mft_record_number()) + str(r.flags()))
    def mft_record_build_path(self, record, cycledetector=None):
        if cycledetector == None:
            cycledetector = {}
        rec_num = record.mft_record_number() & 0xFFFFFFFFFFFF
        if record.mft_record_number() & 0xFFFFFFFFFFFF == 0x0005:
            if self.prefix:
                return self.prefix
            else:
                return "\\."
        fn = record.filename_information()
        if not fn:
            return "\\??"
        parent_record_num = fn.mft_parent_reference() & 0xFFFFFFFFFFFF
        parent_buf = self.mft_get_record_buf(parent_record_num)
        if parent_buf == array.array("B", ""):
            return "\\??\\" + fn.filename()
        parent = MFTRecord(parent_buf, 0, False)
        if parent.sequence_number() != fn.mft_parent_reference() >> 48:
            return "\\$OrphanFiles\\" + fn.filename()
        if rec_num in cycledetector:
            debug("Cycle detected")
            if self.prefix:
                return self.prefix + "\\<CYCLE>"
            else:
                return "\\<CYCLE>"
        cycledetector[rec_num] = True
        return self.mft_record_build_path(parent, cycledetector) + "\\" + fn.filename()

    def mft_get_record_by_path(self, path):
        # TODO could optimize here by trying to use INDX buffers
        # and actually walk through the FS
        count = -1
        for record in self.record_generator():
            count += 1
            if record.magic() != 0x454C4946:
                continue
            if not record.is_active():
                continue
            record_path = self.mft_record_build_path(record, {})
            if record_path.lower() != path.lower():
                continue
            return record
        return False

    def read(self, offset, length):
        if self.filetype == "image":
            with open(self.filename, "rb") as f:
                f.seek(offset)
                return array.array("B", f.read(length))
        return array.array("B", "")


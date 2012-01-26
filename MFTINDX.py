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

import struct, time, array, sys, cPickle, re, os, calendar
from datetime import datetime
import types

import argparse
global verbose

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
        offset_length = self.header() >> 4
        length_length = self.header() & 0xF
        self.declare_field("binary", "length_binary", self.current_field_offset(), length_length)
        self.declare_field("binary", "offset_binary", self.current_field_offset(), offset_length)

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

    def entries(self):
        ret = []
        offset = self.offset()
        entry = Runentry(self._buf, offset, self)
        while entry.header() != 0:
            ret.append(entry)
            offset += entry.size()
            entry = Runentry(self._buf, offset, self)
        return ret

    def runs(self):
        """
        Yields tuples (volume offset, length).
        Recall that the entries are relative to one another
        """
        last_offset = 0
        for e in self.entries():
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

class NTFSFile():
    def __init__(self, options):
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

def information_bodyfile(path, size, inode, info, attributes=None):
    if not attributes:
        attributes = []
    try:
        modified = int(calendar.timegm(info.modified_time().timetuple()))    
    except (ValueError, AttributeError):
        modified = int(calendar.timegm(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        accessed = int(calendar.timegm(info.accessed_time().timetuple()))
    except (ValueError, AttributeError):
        accessed = int(calendar.timegm(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        changed  = int(calendar.timegm(info.changed_time().timetuple()))
    except (ValueError, AttributeError):
        changed = int(calendar.timegm(datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    try:
        created  = int(calendar.timegm(info.created_time().timetuple()))
    except (ValueError, AttributeError):
        created = int(calendar.timegm(datetime.min.timetuple()))
    attributes_text = ""
    if len(attributes) > 0:
        attributes_text = " (%s)" % (", ".join(attributes))
    return u"0|%s|%s|0|0|0|%s|%s|%s|%s|%s\n" % (path + attributes_text, inode,
                                              size, modified, accessed, changed, 
                                              created)

def record_bodyfile(ntfsfile, record, inode=None, attributes=None):
    if not attributes:
        attributes = []
    path = ntfsfile.mft_record_build_path(record, {})
    si = record.standard_information()
    fn = record.filename_information()
    if not fn:
        raise InvalidAttributeException("Unable to parse attribute")
    inode = record.inode or record.mft_record_number()
    size = fn.logical_size()
    if not si:
        si_half = ""
    else:
        si_half = information_bodyfile(path, size, inode, si, attributes)
    attributes.append("filename")
    fn_half = information_bodyfile(path, size, inode, fn, attributes=attributes)
    return "%s%s" % (si_half, fn_half)

def node_header_bodyfile(options, node_header, basepath):
    ret = ""
    attrs = ["filename", "INDX"]
    if options.indxlist:
        for e in node_header.entries():
            path = basepath + "\\" + e.filename_information().filename()
            size = e.filename_information().logical_size()
            inode = 0
            ret += information_bodyfile(path, size, inode, 
                                        e.filename_information(), attributes=attrs)
    attrs.append("slack")
    if options.slack:
        for e in node_header.slack_entries():
            path = basepath + "\\" + e.filename_information().filename()
            size = e.filename_information().logical_size()
            inode = 0
            ret += information_bodyfile(path, size, inode, 
                                        e.filename_information(), attributes=attrs)
    return ret

def record_indx_entries_bodyfile(options, ntfsfile, record):
    # TODO handle all possible errors here
    f = ntfsfile
    ret = ""
    if not record:
        return ret
    basepath = f.mft_record_build_path(record, {})
    indxroot = record.attribute(ATTR_TYPE.INDEX_ROOT)
    if indxroot:
        if indxroot.non_resident() != 0:
            # TODO this shouldn't happen.
            pass
        else:
            irh = IndexRootHeader(indxroot.value(), 0, False)
            nh = irh.node_header()
            ret += node_header_bodyfile(options, nh, basepath)
    extractbuf = array.array("B")
    for attr in record.attributes():
        if attr.type() != ATTR_TYPE.INDEX_ALLOCATION:
            continue
        if attr.non_resident() != 0:
            for (offset, length) in attr.runlist().runs():
                try:
                    extractbuf += f.read(offset * options.clustersize + options.offset,
                                         length * options.clustersize)
                except IOError:
                    pass
        else:
            extractbuf += array.array("B", attr.value())
    if len(extractbuf) < 4096: # TODO make this INDX record size
        return ret
    offset = 0
    try:
        irh = IndexRecordHeader(extractbuf, offset, False)
    except OverrunBufferException: 
        return ret
    while irh.magic() == 0x58444E49: # TODO could miss something if there is an empty, valid record at the end
        nh = irh.node_header()
        ret += node_header_bodyfile(options, nh, basepath)
        # TODO get this from the boot record
        offset += options.clustersize
        if offset + 4096 > len(extractbuf): # TODO make this INDX record size
            return ret
        try:
            irh = IndexRecordHeader(extractbuf, offset, False)
        except OverrunBufferException: 
            return ret
    return ret

def try_write(s):
    try:
        sys.stdout.write(s)
    except UnicodeEncodeError, UnicodeDecodeError:
        warning("Failed to write string due to encoding issue: " + str(list(s)))

def print_nonresident_indx_bodyfile(options, buf, basepath=""):
    offset = 0
    try:
        irh = IndexRecordHeader(buf, offset, False)
    except OverrunBufferException: 
        return 
    while irh.magic() == 0x58444E49: # TODO could miss something if there is an empty, valid record at the end
        nh = irh.node_header()
        try_write(node_header_bodyfile(options, nh, basepath))
        offset += options.clustersize
        if offset + 4096 > len(buf): # TODO make this INDX record size
            return 
        try:
            irh = IndexRecordHeader(buf, offset, False)
        except OverrunBufferException: 
            return
    return    

def print_bodyfile(options):
    if options.filetype == "mft" or options.filetype == "image":
        f = NTFSFile(options)
        if options.filter:
            refilter = re.compile(options.filter)
        for record in f.record_generator():
            debug("Considering MFT record %s" % (record.mft_record_number()))
            try:
                if record.magic() != 0x454C4946:
                    debug("Record has a bad magic value")
                    continue
                if options.filter:
                    path = f.mft_record_build_path(record, {})
                    if not refilter.search(path):
                        debug("Skipping listing path due to regex filter: " + path)
                        continue
                if record.is_active() and options.mftlist:
                    try_write(record_bodyfile(f, record))
                if options.indxlist or options.slack:
                    try_write(record_indx_entries_bodyfile(options, f, record))
                elif (not record.is_active()) and options.deleted:
                    try_write(record_bodyfile(f, record, attributes=["deleted"]))
                if options.filetype == "image" and \
                   (options.indxlist or options.slack):
                    extractbuf = array.array("B")
                    found_indxalloc = False
                    for attr in record.attributes():
                        if attr.type() != ATTR_TYPE.INDEX_ALLOCATION:
                            continue
                        found_indxalloc = True
                        if attr.non_resident() != 0:
                            for (offset, length) in attr.runlist().runs():
                                extractbuf += f.read(offset * options.clustersize + options.offset, length * options.clustersize)
                        else:
                            pass # This shouldn't happen.
                    if found_indxalloc and len(extractbuf) > 0:
                        path = f.mft_record_build_path(record, {})
                        print_nonresident_indx_bodyfile(options, extractbuf, basepath=path)
            except InvalidAttributeException:
                pass
    elif options.filetype == "indx":
        with open(options.filename, "rb") as f:
            buf = array.array("B", f.read())
        print_nonresident_indx_bodyfile(options, buf)

def print_indx_info(options):
    f = NTFSFile(options)
    try:
        record_num = int(options.infomode)
        record_buf = f.mft_get_record_buf(record_num)
        record = MFTRecord(record_buf, 0, False)
    except ValueError:
        record = f.mft_get_record_by_path(options.infomode)
    if not record:
        print "Did not find directory entry for " + options.infomode
        return
    print "Found directory entry for: " + options.infomode
    print "Path: " + f.mft_record_build_path(record, {})
    print "MFT Record: " + str(record.mft_record_number())
    indxroot = record.attribute(ATTR_TYPE.INDEX_ROOT)
    if not indxroot:
        print "No INDX_ROOT attribute"
        return 
    print "Found INDX_ROOT attribute"
    if indxroot.non_resident() != 0:
        # This shouldn't happen.
        print "INDX_ROOT attribute is non-resident"
        for e in indxroot.runlist().entries():
            print "Cluster %s, length %s" % (hex(e.offset()), hex(e.length()))            
    else:
        print "INDX_ROOT attribute is resident"
        irh = IndexRootHeader(indxroot.value(), 0, False)
        someentries = False
        for e in irh.node_header().entries():
            if not someentries:
                print "INDX_ROOT entries:"
            someentries = True
            print "  " + e.filename_information().filename()
        if not someentries:
            print "INDX_ROOT entries: (none)"
        someentries = False
        for e in irh.node_header().slack_entries():
            if not someentries:
                print "INDX_ROOT slack entries:"
            someentries = True
            print "  " + e.filename_information().filename()
        if not someentries:
            print "INDX_ROOT slack entries: (none)"
        extractbuf = array.array("B")
        found_indxalloc = False
        for attr in record.attributes():
            if attr.type() != ATTR_TYPE.INDEX_ALLOCATION:
                continue
            found_indxalloc = True
            print "Found INDX_ALLOCATION attribute"
            if attr.non_resident() != 0:
                print "INDX_ALLOCATION is non-resident"
                for (offset, length) in attr.runlist().runs():
                    print "Cluster %s, length %s" % (hex(offset), hex(length))
                    print "  Using clustersize %s (%s) bytes and volume offset %s (%s) bytes: \n  %s (%s) bytes for %s (%s) bytes" % \
                        (options.clustersize, hex(options.clustersize),
                         options.offset, hex(options.offset),
                         offset * options.clustersize + options.offset, hex(offset * options.clustersize + options.offset),
                         length * options.clustersize, hex(length * options.clustersize))
                    extractbuf += f.read(offset * options.clustersize + options.offset, length * options.clustersize)
            else:
                # This shouldn't happen.
                print "INDX_ALLOCATION is resident"
        if not found_indxalloc:
            print "No INDX_ALLOCATION attribute found"
            return
        if options.extract:
            with open(options.extract, "wb") as g:
                g.write(extractbuf)
    return 
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse NTFS filesystem structures.')
    parser.add_argument('-t', action="store", metavar="type", nargs=1, dest="filetype", help="Type of input file. One of 'image', 'MFT', or 'INDX'")
    parser.add_argument('-c', action="store", metavar="size", nargs=1, type=int, dest="clustersize", help="Use this cluster size in bytes (default 4096 bytes)")
    parser.add_argument('-o', action="store", metavar="offset", nargs=1, type=int, dest="offset", help="Offset in bytes to volume in image (default 32256 bytes)")
    parser.add_argument('-l', action="store_true", dest="indxlist", help="List file entries in INDX records")
    parser.add_argument('-s', action="store_true", dest="slack", help="List file entries in INDX slack space")
    parser.add_argument('-m', action="store_true", dest="mftlist", help="List file entries for active MFT records")
    parser.add_argument('-d', action="store_true", dest="deleted", help="List file entries for MFT records marked as deleted")
    parser.add_argument('-i', action="store", metavar="path|inode", nargs=1, dest="infomode", help="Print information about a path's INDX records")
    parser.add_argument('-e', action="store", metavar="i30", nargs=1, dest="extract", help="Used with -i, extract INDX_ALLOCATION attribute to a file")
    parser.add_argument('-f', action="store", metavar="regex", nargs=1, dest="filter", help="Only consider entries whose path matches this regular expression")
    parser.add_argument('-p', action="store", metavar="prefix", nargs=1, dest="prefix", help="Prefix paths with `prefix` rather than \\.\\")
    parser.add_argument('--progress', action="store_true", dest="progress", help="Update a status indicator on STDERR if STDOUT is redirected")
    parser.add_argument('-v', action="store_true", dest="verbose", help="Print debugging information")
    parser.add_argument('filename', action="store", help="Input INDX file path")

    results = parser.parse_args()

    global verbose
    verbose = results.verbose

    if results.filetype:
        results.filetype = results.filetype[0].lower()
        info("Asked to process a file with type: " + results.filetype)
    else:
        with open(results.filename, "rb") as f:
            b = f.read(1024)
            if b[0:4] == "FILE": 
                results.filetype = "mft"
            elif b[0:4] == "INDX":
                results.filetype = "indx"
            else:
                results.filetype = "image"
        info("Auto-detected input file type: " + results.filetype)
    
    if results.clustersize:
        results.clustersize = results.clustersize[0]
        info("Using explicit file system cluster size %s (%s) bytes" % (str(results.clustersize), hex(results.clustersize)))
    else:
        results.clustersize = 4096
        info("Assuming file system cluster size %s (%s) bytes" % (str(results.clustersize), hex(results.clustersize)))        

    if results.offset:
        results.offset = results.offset[0]
        info("Using explicit volume offset %s (%s) bytes" % (str(results.offset), hex(results.offset)))
    else:
        results.offset = 32256
        info("Assuming volume offset %s (%s) bytes" % (str(results.offset), hex(results.offset)))        

    if results.prefix:
        results.prefix = results.prefix[0]
        info("Using path prefix " + results.prefix)

    if results.indxlist:
        info("Asked to list entries in INDX records")
        if results.filetype == "mft":
            info("  Note, only resident INDX records can be processed with an MFT input file")
            info("  If you find an interesting record, use -i to identify the relevant INDX record clusters")
        elif results.filetype == "indx":
            info("  Note, only records in this INDX record will be listed")
        elif results.filetype == "image":
            pass
        else:
            pass
            
    if results.slack:
        info("Asked to list slack entries in INDX records")
        info("  Note, this uses a scanning heuristic to identify records. These records may be corrupt or out-of-date.")
    
    if results.mftlist:
        info("Asked to list active file entries in the MFT")
        if results.filetype == "indx":
            error("Cannot list MFT entries of an INDX record")

    if results.deleted:
        info("Asked to list deleted file entries in the MFT")
        if results.filetype == "indx":
            error("Cannot list MFT entries of an INDX record")

    if results.infomode:
        results.infomode = results.infomode[0]
        info("Asked to list information about path " + results.infomode)
        if results.indxlist or \
           results.slack or \
           results.mftlist or \
           results.deleted:
            error("Information mode (-i) cannot be run with file entry list modes (-l/-s/-m/-d)")

        if results.extract:
            results.extract = results.extract[0]
            info("Asked to extract INDX_ALLOCATION attribute for the path " + results.infomode)

    if results.extract and not results.infomode:
        warning("Extract (-e) doesn't make sense without information mode (-i)")

    if results.extract and not results.filetype == "image":
        error("Cannot extract non-resident attributes from anything but an image")

    if not (results.indxlist or \
            results.slack or \
            results.mftlist or \
            results.deleted or \
            results.infomode):
        error("You must choose a mode (-i/-l/-s/-m/-d)")
            
    if results.filter:
        results.filter = results.filter[0]
        info("Asked to only list file entry information for paths matching the regular expression: " + results.filter)
        if results.infomode:
            warning("This filter has no meaning with information mode (-i)")

    if results.infomode:
        print_indx_info(results)
    elif results.indxlist or \
         results.slack or \
         results.mftlist or \
         results.deleted:
        print_bodyfile(results)
    



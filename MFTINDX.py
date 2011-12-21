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

import struct, time, array, sys
from datetime import datetime

import argparse
global verbose

def debug(message):
    global verbose
    if verbose:
        print "# [d] %s" % (message)

def warning(message):
    print "# [w] %s" % (message)

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

    def _prepare_fields(self, fields=False):
        """
        Declaratively add fields to this block.
        self._fields should contain a list of tuples ("type", "name", offset).
        This method will dynamically add corresponding offset and unpacker methods
        to this block.
        Arguments:
        - `fields`: (Optional) A list of tuples to add. Otherwise, 
        self._fields is used.
        """
        for field in fields:
            def handler():
                f = getattr(self, "unpack_" + field[0])
                return f(*(field[2:]))
            setattr(self, field[1], handler)
            debug("(%s) %s\t@ %s\t: %s" % (field[0].upper(), 
                                           field[1], 
                                           hex(self.absolute_offset(field[2])),
                                           str(handler())))
            setattr(self, "_off_" + field[1], field[2])

    def declare_field(self, type, name, offset=False, length=False):
        """
        A shortcut to add a field.
        Arguments:
        - `type`: A string. Should be one of the unpack_* types.
        - `name`: A string. 
        - `offset`: A number.
        - `length`: (Optional) A number.
        """
        if not offset:
            offset = self._implicit_offset
        if length:
            self._prepare_fields([(type, name, offset, length)])
        else:
            self._prepare_fields([(type, name, offset)])

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
        elif type == "binary" and length:
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

    def unpack_binary(self, offset, length):
        """
        Returns raw binary data from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the binary blob.
        Throws:
        - `OverrunBufferException`
        """
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
        return self._buf[self._offset + offset:self._offset + offset + 2 * length].tostring().decode("utf16")

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
            debug("Fixup verified at %s and patched from %s to %s." % (hex(self.offset() + fixup_offset),
                                                                       hex(fixup_value), hex(check_value)))

class IndexRootHeader(Block):
    def __init__(self, buf, offset, parent):
        debug("INDEX ROOT HEADER at %s." % (hex(offset)))
        super(IndexRootHeader, self).__init__(buf, offset, parent)
        self.declare_field("dword", "type", 0x0)
        self.declare_field("dword", "collation_rule")
        self.declare_field("dword", "index_record_size_bytes")
        self.declare_field("byte",  "index_record_size_clusters")
        self.declare_field("dword", "unused")

class IndexNodeHeader(Block):
    def __init__(self, buf, offset, parent):
        debug("INDEX NODE HEADER at %s." % (hex(offset)))
        super(IndexNodeHeader, self).__init__(buf, offset, parent)
        self.declare_field("dword", "entry_list_start", 0x0)
        self.declare_field("dword", "entry_list_end")
        self.declare_field("dword", "entry_list_allocation_end")
        self.declare_field("dword", "flags")
        self.declare_field("binary", "list_buffer", self.entry_list_start(), self.entry_list_allocation_end() - self.entry_list_start())

class IndexEntry2(Block):
    def __init__(self, buf, offset, parent):
        debug("INDEX ENTRY at %s." % (hex(offset)))
        super(IndexEntry2, self).__init__(buf, offset, parent)
        self.declare_field("qword", "mft_reference", 0x0)
        self.declare_field("word", "length")
        self.declare_field("word", "filename_information_length")
        self.declare_field("dword", "flags")
        if self.filename_information_length() > 0:
            self.declare_field("binary", "filename_information_buffer", self.current_field_offset(), self.filename_information_length())
        self.declare_field("qword", "child_vcn", align(self.current_field_offset(), 0x8))

class FilenameAttribute(Block):
    def __init__(self, buf, offset, parent):
        debug("Filename attribute at %s." % (hex(offset)))
        super(FilenameAttribute, self).__init__(buf, offset, parent)
        self.declare_field("qword", "mft_reference", 0x0)
        self.declare_field("word", "length")
        self.declare_field("word", "filename_information_length")
        self.declare_field("dword", "flags")
        if self.filename_information_length() > 0:
            self.declare_field("binary", "filename_information_buffer", self.current_field_offset(), self.filename_information_length())
            self.declare_field("qword", "child_vcn", align(self.current_field_offset(), 0x8))
    

class IndexEntry(Block):
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent NTATTR_STANDARD_INDEX_HEADER block, which links to this block.
        """
        debug("INDEX ENTRY at %s." % (hex(offset)))
        super(IndexEntry, self).__init__(buf, offset, parent)

        self.declare_field("windows_timestamp", "created_time", 0x18)
        self.declare_field("windows_timestamp", "modified_time")
        self.declare_field("windows_timestamp", "changed_time")
        self.declare_field("windows_timestamp", "accessed_time")
        self.declare_field("qword", "physical_size")
        self.declare_field("qword", "logical_size")

        self.declare_field("byte", "filename_length", 0x50)
        self.declare_field("byte", "filename_type")
        self.declare_field("wstring", "filename", 0x52, self.filename_length()) #TODO check this

        if self.filename_type() > 4:
            warning("Invalid INDX record entry filename type at 0x%s" % (hex(self.offset() + self._filename_type_offset)))

    def end_offset(self):
        """
        return the first address not a part of this block
        """
        string_end = self.offset() + self._filename_offset + 2 * self.filename_length()
        return align(string_end, 8)

    def has_next(self):
        return self.end_offset() - self.parent().offset() <= self.parent().entry_size()
        
    def next(self):
        """
        return the next entry after this one.
        warning, this does not check to see if another exists, but blindly creates one
        from the next data in the buffer. check NTATTR_STANDARD_INDEX_ENTRY.has_next() first
        """
        return IndexEntry(self._buf, self.end_offset(), self.parent())

    def parse_time_safe(self, offset):
        """
        The *_safe time methods return the date of the
        UNIX epoch if there is an exception parsing the 
        date
        """
        try:
            return self.parse_time(offset)
        except ValueError:
            debug("Timestamp is invalid, using a default.")
            return datetime(1970, 1, 1, 0, 0, 0)

    def created_time_safe(self):
        return self.parse_time_safe(self._created_time_offset)

    def modified_time_safe(self):
        return self.parse_time_safe(self._modified_time_offset)
        
    def changed_time_safe(self):
        return self.parse_time_safe(self._changed_time_offset)

    def accessed_time_safe(self):
        return self.parse_time_safe(self._accessed_time_offset)

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

class IndexEntryHeader(FixupBlock):
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        debug("INDX HEADER @ %s." % (hex(offset)))
        super(IndexEntryHeader, self).__init__(buf, offset, parent)

        _magic = self.unpack_string(0, 4)
        if _magic != "INDX":
            raise ParseException("Invalid INDX ID")

        self.declare_field("dword", "entry_size", 0x1C)
        self.declare_field("dword", "allocated_size")

        self.fixup(self.unpack_word(0x6), 0x28)

    def entry_offset(self):
        string_end = self.offset() + 0x2A + 2 * self.unpack_word(0x6)
        return align(string_end, 8)

    def entries(self):
        """
        A generator that returns each INDX entry associated with this header.
        """
        if self.entry_offset() - self.offset()  >= self.entry_size():
            debug("No entries in this allocation block.")
            return 

        e = IndexEntry(self._buf, self.entry_offset(), self)
        yield e

        while e.has_next():
            debug("Entry has another entry after it.")
            e = e.next()
            yield e
            debug("No more entries.")

    def slack(self):
        return self._buf[self.offset() + self.entry_size():self.offset() + self.entry_allocated_size()]
        
    def end_offset(self):
        return self.offset() + self.entry_allocated_size()

    def deleted_entries(self):
        """
        A generator that yields INDX entries found in the slack space
        associated with this header.
        """
        off = self.offset() + self.entry_size()

        try:
            while off < self.offset() + self.entry_allocated_size() - 0x52:
                try:
                    debug("Trying to find slack entry at %s." % (hex(off)))
                    e = SlackIndexEntry(self._buf, off, self)
                    if e.is_valid():
                        debug("Slack entry is valid.")
                        off = e.end_offset()
                        yield e
                    else:
                        debug("Slack entry is invalid.")
                        raise ParseException("Not a deleted entry")
                except ParseException:
                    debug("Scanning one byte forward.")
                    off += 1
        except struct.error:
            debug("Slack entry parsing overran buffer.")
            pass

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

def record_generator(filename):
    with open(filename, "rb") as f:
        record = f.read(1024)
        while record:
            yield record
            record = array.array("B", f.read(1024))

def mft_get_record_buf(filename, number):
    with open(filename, "rb") as f:
        f.seek(number * 1024)
        return array.array("B", f.read(1024))

def doit(filename, directory):
    buf = mft_get_record_buf(filename, 5)
    m = MFTRecord(buf, 0, False)
    indx = m.attribute(ATTR_TYPE.INDEX_ROOT)
    h = IndexEntryHeader(indx._buf, indx.absolute_offset(0x0), False)
    for e in h.entries():
        print e.filename()


    # buf = mft_get_record_buf(filename, 1)
    # m = MFTRecord(buf, 0, False)

    # buf = mft_get_record_buf(filename, 2)
    # m = MFTRecord(buf, 0, False)

if __name__ == '__main__':
    global verbose
    verbose = True

    doit(sys.argv[1], sys.argv[2])



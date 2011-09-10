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

import struct, argparse, time
from datetime import datetime

def parse_windows_timestamp(qword):
    # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
    return datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)

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

    def unpack_string(self, offset, length):
        """
        Returns a string from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the string.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<%ds" % (length), self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

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
        return self._buf[self._offset + offset:self._offset + offset + 2 * length].decode("utf16")

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

class NTATTR_STANDARD_INDEX_HEADER(Block):
# 0x0         char magicNumber[4]; // == "INDX"
    
# 0x4         unsigned short updatedSequenceArrayOffset;
# 0x6         unsigned short sizeOfUpdatedSequenceNumberInWords;
    
# 0x8         LONGLONG logFileSeqNum;
# 0x10        LONGLONG thisVirtualClusterNumber;
    
# 0x18        DWORD indexEntryOffset;
# 0x1C        DWORD sizeOfEntries;
# 0x20        DWORD sizeOfEntriesAlloc;
    
# 0x24        BYTE flags;
# 0x25        BYTE padding[3];
    
# 0x28        unsigned short updateSeq;
# 0x2A        WORD updatedSequenceArray[sizeOfUpdatedSequenceNumberInWords];

    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        super(NTATTR_STANDARD_INDEX_HEADER, self).__init__(buf, offset, parent)

        _magic = self.unpack_string(0, 4)
        if _magic != "INDX":
            raise ParseException("Invalid INDX ID")

        self._entry_size_offset = 0x1C
        self._entry_allocated_size_offset = 0x20

    def entry_offset(self):
        string_end = self.offset() + 0x2A + 2 * self.unpack_word(0x6)
        return align(string_end, 8)

    def entry_size(self):
        return self.unpack_dword(0x1C)

    def entry_allocated_size(self):
        return self.unpack_dword(0x20)

    def entries(self):
        """
        A generator that returns each INDX entry associated with this header.
        """
        e = NTATTR_STANDARD_INDEX_ENTRY(self._buf, self.entry_offset(), self)
        yield e

        while e.has_next():
            e = e.next()
            yield e

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

        # NTATTR_STANDARD_INDEX_ENTRY is at least 0x52 bytes
        # long, so don't overrun
        # but if we do, then we're done
        try:
            while off < self.offset() + self.entry_allocated_size() - 0x52:
                try:
                    e = NTATTR_STANDARD_INDEX_SLACK_ENTRY(self._buf, off, self)
                    if e.is_valid():
                        off = e.end_offset()
                        yield e
                    else:
                        raise ParseException("Not a deleted entry")
                except ParseException:
                    off += 1
        except struct.error:
            pass

class NTATTR_STANDARD_INDEX_ENTRY(Block):
# 0x0    LONGLONG mftReference;
# 0x8    unsigned short sizeOfIndexEntry;
# 0xA    unsigned short sizeOfStream;
    
# 0xC    unsigned short flags;
# 0xE    BYTE padding[2];

# 0x10    LONGLONG refParentDirectory;
    
# 0x18    FILETIME creationTime;
# 0x20    FILETIME lastModifiedTime;
# 0x28    FILETIME MFTRecordChangeTime;
# 0x30    FILETIME lastAccessTime;
# 0x38    LONGLONG physicalSizeOfFile;
# 0x40    LONGLONG logicalSizeOfFile;
# 0x48    DWORD    flags;
# 0x4C    DWORD    extendedAttributes;
    
# 0x50    unsigned BYTE filenameLength;
# 0x51    NTFS_FNAME_NSPACE filenameType;

# 0x52    wchar_t filename[filenameLength];

# 0xXX    Padding to 8-byte boundary

    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent NTATTR_STANDARD_INDEX_HEADER block, which links to this block.
        """
        super(NTATTR_STANDARD_INDEX_ENTRY, self).__init__(buf, offset, parent)

        self._created_time_offset = 0x18
        self._modified_time_offset = 0x20
        self._changed_time_offset = 0x28
        self._accessed_time_offset = 0x30

        self._physical_size_offset = 0x38
        self._logical_size_offset = 0x40

        self._filename_length_offset = 0x50      
        self._filename_type_offset = 0x51
        self._filename_offset = 0x52

        if self.unpack_byte(self._filename_type_offset) > 4:
            raise ParseException("Invalid INDX record entry filename type")

    def end_offset(self):
        """
        return the first address not a part of this block
        """
        string_end = self.offset() + self._filename_offset + \
             2 * self.unpack_byte(self._filename_length_offset)

        return align(string_end, 8)

    def has_next(self):
        return self.end_offset() - self.parent().offset() < self.parent().entry_size()
        
    def next(self):
        """
        return the next entry after this one.
        warning, this does not check to see if another exists, but blindly creates one
        from the next data in the buffer. check NTATTR_STANDARD_INDEX_ENTRY.has_next() first
        """
        return NTATTR_STANDARD_INDEX_ENTRY(self._buf, self.end_offset(), self.parent())

    def parse_time(self, offset):
        return parse_windows_timestamp(self.unpack_qword(offset))

    def created_time(self):
        return self.parse_time(self._created_time_offset)

    def modified_time(self):
        return self.parse_time(self._modified_time_offset)
    
    def changed_time(self):
        return self.parse_time(self._changed_time_offset)

    def accessed_time(self):
        return self.parse_time(self._accessed_time_offset)

    def parse_time_safe(self, offset):
        """
        The *_safe time methods return the date of the
        UNIX epoch if there is an exception parsing the 
        date
        """
        try:
            return self.parse_time(offset)
        except ValueError:
            return datetime(1970, 1, 1, 0, 0, 0)

    def created_time_safe(self):
        """
        The *_safe time methods return the date of the
        UNIX epoch if there is an exception parsing the 
        date
        """
        return self.parse_time_safe(self._created_time_offset)

    def modified_time_safe(self):
        """
        The *_safe time methods return the date of the
        UNIX epoch if there is an exception parsing the 
        date
        """
        return self.parse_time_safe(self._modified_time_offset)
    
    def changed_time_safe(self):
        """
        The *_safe time methods return the date of the
        UNIX epoch if there is an exception parsing the 
        date
        """
        return self.parse_time_safe(self._changed_time_offset)

    def accessed_time_safe(self):
        """
        The *_safe time methods return the date of the
        UNIX epoch if there is an exception parsing the 
        date
        """
        return self.parse_time_safe(self._accessed_time_offset)

    def physical_size(self):
        return self.unpack_qword(self._physical_size_offset)

    def logical_size(self):
        return self.unpack_qword(self._logical_size_offset)

    def filename(self):
        return self.unpack_wstring(self._filename_offset, self.unpack_byte(self._filename_length_offset))

class NTATTR_STANDARD_INDEX_SLACK_ENTRY(NTATTR_STANDARD_INDEX_ENTRY):
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent NTATTR_STANDARD_INDEX_HEADER block, which links to this block.
        """
        super(NTATTR_STANDARD_INDEX_SLACK_ENTRY, self).__init__(buf, offset, parent)

    def is_valid(self):
        recent_date = datetime(1990, 1, 1, 0, 0, 0)
        return self.modified_time_safe() > recent_date and \
                self.accessed_time_safe() > recent_date and \
                self.changed_time_safe() > recent_date and \
                self.created_time_safe() > recent_date

def entry_csv(entry, filename=False):
    if filename:
        fn = filename
    else:
        fn = entry.filename()
    return u"%s,\t%s,\t%s,\t%s,\t%s,\t%s,\t%s" % (fn, entry.physical_size(),
                                                  entry.logical_size(), entry.modified_time_safe(),
                                                  entry.accessed_time_safe(), entry.changed_time_safe(),
                                                  entry.created_time_safe())

def entry_bodyfile(entry, filename=False):
    if filename:
        fn = filename
    else:
        fn = entry.filename()

    try:
        modified = int(time.mktime(entry.modified_time_safe().timetuple()))    
    except ValueError:
        modified = int(time.mktime(datetime.min.timetuple()))

    try:
        accessed = int(time.mktime(entry.accessed_time_safe().timetuple()))
    except ValueError:
        accessed = int(time.mktime(datetime.min.timetuple()))

    try:
        changed  = int(time.mktime(entry.changed_time_safe().timetuple()))
    except ValueError:
        changed = int(time.mktime(datetime.min.timetuple()))

    try:
        created  = int(time.mktime(entry.created_time_safe().timetuple()))
    except ValueError:
        created = int(time.mktime(datetime.min.timetuple()))

    return u"0|%s|0|0|0|0|%s|%s|%s|%s|%s" % (fn, entry.logical_size(), modified, accessed, changed, created)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse NTFS INDX files.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-c', action="store_true", dest="csv", default=False, help="Output CSV")
    group.add_argument('-b', action="store_true", dest="bodyfile", default=False, help="Output Bodyfile")
    parser.add_argument('-d', action="store_true", dest="deleted", help="Find entries in slack space")
    parser.add_argument('filename', action="store", help="Input INDX file path")
    results = parser.parse_args()

    do_csv = results.csv or \
        (not results.csv and not results.bodyfile)

    if do_csv:
        print "FILENAME,\tPHYSICAL SIZE,\tLOGICAL SIZE,\tMODIFIED TIME,\tACCESSED TIME,\tCHANGED TIME,\tCREATED TIME"

    with open(results.filename) as f:
        b = f.read()

    off = 0
    while off < len(b):
        h = NTATTR_STANDARD_INDEX_HEADER(b, off, False)
        for e in h.entries():
            if do_csv:
                try:
                    print entry_csv(e)
                except UnicodeEncodeError:
                    print entry_csv(e, e.filename().encode("ascii", "replace") + " (error decoding filename)")
            elif results.bodyfile:
                try:
                    print entry_bodyfile(e)
                except UnicodeEncodeError:
                    print entry_bodyfile(e, e.filename().encode("ascii", "replace") + " (error decoding filename)")
        if results.deleted:
            for e in h.deleted_entries():
                fn = e.filename() + " (slack at %s)" % (hex(e.offset()))
                bad_fn = e.filename().encode("ascii", "replace") + " (slack at %s)(error decoding filename)" % (hex(e.offset()))
                if do_csv:
                    try:
                        print entry_csv(e, fn)
                    except UnicodeEncodeError:
                        print entry_csv(e, bad_fn)
                elif results.bodyfile:
                    try:
                        print entry_bodyfile(e, fn)
                    except UnicodeEncodeError:
                        print entry_bodyfile(e, bad_fn)

        off = align(h.end_offset(), 4096)





#!/bin/python

import sys,struct
from datetime import datetime

def parse_windows_timestamp(qword):
    # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
    return datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600 )

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
        """
        return struct.unpack_from("<B", self._buf, self._offset + offset)[0]

    def unpack_word(self, offset):
        """
        Returns a little-endian WORD (2 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        """
        return struct.unpack_from("<H", self._buf, self._offset + offset)[0]

    def unpack_dword(self, offset):
        """
        Returns a little-endian DWORD (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        """
        return struct.unpack_from("<I", self._buf, self._offset + offset)[0]

    def unpack_int(self, offset):
        """
        Returns a little-endian signed integer (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        """
        return struct.unpack_from("<i", self._buf, self._offset + offset)[0]

    def unpack_qword(self, offset):
        """
        Returns a little-endian QWORD (8 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        """
        return struct.unpack_from("<Q", self._buf, self._offset + offset)[0]

    def unpack_string(self, offset, length):
        """
        Returns a string from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the string.
        """
        return struct.unpack_from("<%ds" % (length), self._buf, self._offset + offset)[0]

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
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        super(NTATTR_STANDARD_INDEX_HEADER, self).__init__(buf, offset, parent)

        comment ="""
0x0         char magicNumber[4]; // == "INDX"
    
0x4         unsigned short updatedSequenceArrayOffset;
0x6         unsigned short sizeOfUpdatedSequenceNumberInWords;
    
0x8         LONGLONG logFileSeqNum;
0x10        LONGLONG thisVirtualClusterNumber;
    
0x18        DWORD indexEntryOffset;
0x1C        DWORD sizeOfEntries;
0x20        DWORD sizeOfEntriesAlloc;
    
0x24        BYTE flags;
0x25        BYTE padding[3];
    
0x28        unsigned short updateSeq;
0x2A        WORD updatedSequenceArray[sizeOfUpdatedSequenceNumberInWords];
"""

        _magic = self.unpack_string(0, 4)
        if _magic != "INDX":
            raise ParseException("Invalid INDX ID")

    def entry_offset(self):
        return self.offset + 0x28 + self.unpack_dword(0x6)

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
        return self._buf[self.entry_size():self.entry_allocated_size()]
    
    def end_offset(self):
        return self.offset() + self.entry_allocated_size()

class NTATTR_STANDARD_INDEX_ENTRY(Block):
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent NTATTR_STANDARD_INDEX_HEADER block, which links to this block.
        """
        super(NTATTR_STANDARD_INDEX_ENTRY, self).__init__(buf, offset, parent)

        if self.unpack_byte(0x4A) > 4:
            raise ParseException("Invalid INDX record entry filename type")

        comment ="""
0x0    LONGLONG mftReference;
0x8    unsigned short sizeOfIndexEntry;
0xA    unsigned short sizeOfStream;
    
0xC    unsigned short flags;
0xE    BYTE padding[2];

0x10    LONGLONG refParentDirectory;
    
0x18    FILETIME creationTime;
0x20    FILETIME lastModifiedTime;
0x28    FILETIME MFTRecordChangeTime;
0x30    FILETIME lastAccessTime;
0x38    LONGLONG physicalSizeOfFile;
0x40    LONGLONG logicalSizeOfFile;
0x44    DWORD    flags;
0x48    DWORD    extendedAttributes;
    
0x49    unsigned BYTE filenameLength;
0x4A    NTFS_FNAME_NSPACE filenameType;

0x4B    wchar_t filename[filenameLength];

0xXX    Padding to 8-byte boundary

"""

    def end_offset(self):
        """
        return the first address not a part of this block
        """
        string_end = self.offset() + 0x4B + 2 * self.unpack_byte(0x49)

        if string_end % 8 == 0:
            return string_end
        return string_end + (8 - string_end % 8) 

    def has_next(self):
        return self.end_offset() - self.parent().offset() < self.parent().entry_size()
        
    def next(self):
        return NTATTR_STANDARD_INDEX_ENTRY(self, self.end_offset(), self.parent())

    def created_time(self):
        return parse_windows_timestamp(self.unpack_qword(0x18))

    def modified_time(self):
        return parse_windows_timestamp(self.unpack_qword(0x20))
    
    def changed_time(self):
        return parse_windows_timestamp(self.unpack_qword(0x28))

    def accessed_time(self):
        return parse_windows_timestamp(self.unpack_qword(0x30))

    def filename(self):
        return self.unpack_wstring(0x4B, self.unpack_byte(0x49))

if __name__ == '__main__':
    
    with open(sys.argv[1]) as f:
        b = f.read()

    off = 0
    while off < len(b):
        h = NTATTR_STANDARD_INDEX_HEADER(b, off, False)
        print "header"
        for e in h.entries():
            print e.filename()
        off = h.end_offset()

        if off % 4096 != 0:
            off += 4096 - (off % 4096)




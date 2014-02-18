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
import array
import os
import sys
import struct
import logging
from datetime import datetime
from collections import OrderedDict  # python 2.7 only

from BinaryParser import Block
from BinaryParser import Nestable
from BinaryParser import memoize
from BinaryParser import align
from BinaryParser import ParseException
from BinaryParser import OverrunBufferException
from BinaryParser import read_byte
from BinaryParser import read_word
from BinaryParser import read_dword
from Progress import NullProgress


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


class FixupBlock(Block):
    def __init__(self, buf, offset, parent):
        super(FixupBlock, self).__init__(buf, offset)

    def fixup(self, num_fixups, fixup_value_offset):
        fixup_value = self.unpack_word(fixup_value_offset)

        for i in range(0, num_fixups - 1):
            fixup_offset = 512 * (i + 1) - 2
            check_value = self.unpack_word(fixup_offset)

            if check_value != fixup_value:
                logging.warning("Bad fixup at %s", hex(self.offset() + fixup_offset))
                continue

            new_value = self.unpack_word(fixup_value_offset + 2 + 2 * i)
            self.pack_word(fixup_offset, new_value)

            check_value = self.unpack_word(fixup_offset)
            logging.debug("Fixup verified at %s and patched from %s to %s.",
                          hex(self.offset() + fixup_offset),
                          hex(fixup_value), hex(check_value))


class INDEX_ENTRY_FLAGS:
    """
    sizeof() == WORD
    """
    INDEX_ENTRY_NODE = 0x1
    INDEX_ENTRY_END = 0x2
    INDEX_ENTRY_SPACE_FILLER = 0xFFFF


class INDEX_ENTRY_HEADER(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(INDEX_ENTRY_HEADER, self).__init__(buf, offset)
        self.declare_field("word", "length", 0x8)
        self.declare_field("word", "key_length")
        self.declare_field("word", "index_entry_flags")  # see INDEX_ENTRY_FLAGS
        self.declare_field("word", "reserved")

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0x10

    def __len__(self):
        return 0x10

    def is_index_entry_node(self):
        return self.index_entry_flags() & INDEX_ENTRY_FLAGS.INDEX_ENTRY_NODE

    def is_index_entry_end(self):
        return self.index_entry_flags() & INDEX_ENTRY_FLAGS.INDEX_ENTRY_END

    def is_index_entry_space_filler(self):
        return self.index_entry_flags() & INDEX_ENTRY_FLAGS.INDEX_ENTRY_SPACE_FILLER


class MFT_INDEX_ENTRY_HEADER(INDEX_ENTRY_HEADER):
    """
    Index used by the MFT for INDX attributes.
    """
    def __init__(self, buf, offset, parent):
        super(MFT_INDEX_ENTRY_HEADER, self).__init__(buf, offset, parent)
        self.declare_field("qword", "mft_reference", 0x0)


class SECURE_INDEX_ENTRY_HEADER(INDEX_ENTRY_HEADER):
    """
    Index used by the $SECURE file indices SII and SDH
    """
    def __init__(self, buf, offset, parent):
        super(SECURE_INDEX_ENTRY_HEADER, self).__init__(buf, offset, parent)
        self.declare_field("word", "data_offset", 0x0)
        self.declare_field("word", "data_length")
        self.declare_field("dword", "reserved")


class INDEX_ENTRY(Block,  Nestable):
    """
    NOTE: example structure. See the more specific classes below.
      Probably do not instantiate.
    """
    def __init__(self, buf, offset, parent):
        super(INDEX_ENTRY, self).__init__(buf, offset)
        self.declare_field(INDEX_ENTRY_HEADER, "header", 0x0)
        self.add_explicit_field(0x10, "string", "data")

    def data(self):
        start = self.offset() + 0x10
        end = start + self.header().key_length()
        return self._buf[start:end]

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_word(buf, offset + 0x8)

    def __len__(self):
        return self.header().length()

    def is_valid(self):
        return True


class MFT_INDEX_ENTRY(Block, Nestable):
    """
    Index entry for the MFT directory index $I30, attribute type 0x90.
    """
    def __init__(self, buf, offset, parent):
        super(MFT_INDEX_ENTRY, self).__init__(buf, offset)
        self.declare_field(MFT_INDEX_ENTRY_HEADER, "header", 0x0)
        self.declare_field(FilenameAttribute, "filename_information")

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_word(buf, offset + 0x8)

    def __len__(self):
        return self.header().length()

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


class SII_INDEX_ENTRY(Block, Nestable):
    """
    Index entry for the $SECURE:$SII index.
    """
    def __init__(self, buf, offset, parent):
        super(SII_INDEX_ENTRY, self).__init__(buf, offset)
        self.declare_field(SECURE_INDEX_ENTRY_HEADER, "header", 0x0)
        self.declare_field("dword", "security_id")

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_word(buf, offset + 0x8)

    def __len__(self):
        return self.header().length()

    def is_valid(self):
        # TODO(wb): test
        return 1 < self.header().length() < 0x30 and \
            1 < self.header().key_lenght() < 0x20


class SDH_INDEX_ENTRY(Block, Nestable):
    """
    Index entry for the $SECURE:$SDH index.
    """
    def __init__(self, buf, offset, parent):
        super(SDH_INDEX_ENTRY, self).__init__(buf, offset)
        self.declare_field(SECURE_INDEX_ENTRY_HEADER, "header", 0x0)
        self.declare_field("dword", "hash")
        self.declare_field("dword", "security_id")

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_word(buf, offset + 0x8)

    def __len__(self):
        return self.header().length()

    def is_valid(self):
        # TODO(wb): test
        return 1 < self.header().length() < 0x30 and \
            1 < self.header().key_lenght() < 0x20


class INDEX_HEADER_FLAGS:
    SMALL_INDEX = 0x0  # MFT: INDX_ROOT only
    LARGE_INDEX = 0x1  # MFT: requires INDX_ALLOCATION
    LEAF_NODE = 0x1
    INDEX_NODE = 0x2
    NODE_MASK = 0x1


class INDEX_HEADER(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(INDEX_HEADER, self).__init__(buf, offset)
        self.declare_field("dword", "entries_offset", 0x0)
        self.declare_field("dword", "index_length")
        self.declare_field("dword", "allocated_size")
        self.declare_field("byte", "index_header_flags")  # see INDEX_HEADER_FLAGS
        # then 3 bytes padding/reserved

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0x1C

    def __len__(self):
        return 0x1C

    def is_small_index(self):
        return self.index_header_flags() & INDEX_HEADER_FLAGS.SMALL_INDEX

    def is_large_index(self):
        return self.index_header_flags() & INDEX_HEADER_FLAGS.LARGE_INDEX

    def is_leaf_node(self):
        return self.index_header_flags() & INDEX_HEADER_FLAGS.LEAF_NODE

    def is_index_node(self):
        return self.index_header_flags() & INDEX_HEADER_FLAGS.INDEX_NODE

    def is_NODE_MASK(self):
        return self.index_header_flags() & INDEX_HEADER_FLAGS.NODE_MASK


class INDEX(Block, Nestable):
    def __init__(self, buf, offset, parent, index_entry_class):
        self._INDEX_ENTRY = index_entry_class
        super(INDEX, self).__init__(buf, offset)
        self.declare_field(INDEX_HEADER, "header", 0x0)
        self.add_explicit_field(self.header().entries_offset(),
                                INDEX_ENTRY, "entries")
        slack_start = self.header().entries_offset() + self.header().index_length()
        self.add_explicit_field(slack_start, INDEX_ENTRY, "slack_entries")

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_dword(buf, offset + 0x8)

    def __len__(self):
        return self.header().allocated_size()

    def entries(self):
        """
        A generator that returns each INDEX_ENTRY associated with this node.
        """
        offset = self.header().entries_offset()
        if offset == 0:
            logging.debug("No entries in this allocation block.")
            return
        while offset <= self.header().index_length() - 0x52:
            logging.debug("Entry has another entry after it.")
            e = self._INDEX_ENTRY(self._buf, self.offset() + offset, self)
            offset += e.length()
            yield e
        logging.debug("No more entries.")

    def slack_entries(self):
        """
        A generator that yields INDEX_ENTRYs found in the slack space
        associated with this header.
        """
        offset = self.header().index_length()
        try:
            while offset <= self.header().allocated_size - 0x52:
                try:
                    logging.debug("Trying to find slack entry at %s.", hex(offset))
                    e = self._INDEX_ENTRY(self._buf, offset, self)
                    if e.is_valid():
                        logging.debug("Slack entry is valid.")
                        offset += e.length() or 1
                        yield e
                    else:
                        logging.debug("Slack entry is invalid.")
                        raise ParseException("Not a deleted entry")
                except ParseException:
                    logging.debug("Scanning one byte forward.")
                    offset += 1
        except struct.error:
            logging.debug("Slack entry parsing overran buffer.")
            pass


def INDEX_ROOT(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(INDEX_ROOT, self).__init__(buf, offset)
        self.declare_field("dword", "type", 0x0)
        self.declare_field("dword", "collation_rule")
        self.declare_field("dword", "index_record_size_bytes")
        self.declare_field("byte",  "index_record_size_clusters")
        self.declare_field("byte", "unused1")
        self.declare_field("byte", "unused2")
        self.declare_field("byte", "unused3")
        self._index_offset = self.current_field_offset()
        self.add_explicit_field(self._index_offset, INDEX, "index")

    def index(self):
        return INDEX(self._buf, self.offset(self._index_offset),
                     self, MFT_INDEX_ENTRY)

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0x10 + INDEX.structure_size(buf, offset + 0x10, parent)

    def __len__(self):
        return 0x10 + len(self.index())


class NTATTR_STANDARD_INDEX_HEADER(Block):
    def __init__(self, buf, offset, parent):
        logging.debug("INDEX NODE HEADER at %s.", hex(offset))
        super(NTATTR_STANDARD_INDEX_HEADER, self).__init__(buf, offset)
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
            return

        # 0x52 is an approximate size of a small index entry
        while offset <= self.entry_list_end() - 0x52:
            e = IndexEntry(self._buf, self.offset() + offset, self)
            offset += e.length()
            yield e

    def slack_entries(self):
        """
        A generator that yields INDX entries found in the slack space
        associated with this header.
        """
        offset = self.entry_list_end()
        try:
            # 0x52 is an approximate size of a small index entry
            while offset <= self.entry_list_allocation_end() - 0x52:
                try:
                    e = SlackIndexEntry(self._buf, offset, self)
                    if e.is_valid():
                        offset += e.length() or 1
                        yield e
                    else:
                        raise ParseException("Not a deleted entry")
                except ParseException:
                    # ensure we're always moving forward
                    offset += 1
        except struct.error:
            pass


class IndexRootHeader(Block):
    def __init__(self, buf, offset, parent):
        logging.debug("INDEX ROOT HEADER at %s.", hex(offset))
        super(IndexRootHeader, self).__init__(buf, offset)
        self.declare_field("dword", "type", 0x0)
        self.declare_field("dword", "collation_rule")
        self.declare_field("dword", "index_record_size_bytes")
        self.declare_field("byte",  "index_record_size_clusters")
        self.declare_field("byte", "unused1")
        self.declare_field("byte", "unused2")
        self.declare_field("byte", "unused3")
        self._node_header_offset = self.current_field_offset()

    def node_header(self):
        return NTATTR_STANDARD_INDEX_HEADER(self._buf,
                               self.offset() + self._node_header_offset,
                               self)


class IndexRecordHeader(FixupBlock):
    def __init__(self, buf, offset, parent):
        logging.debug("INDEX RECORD HEADER at %s.",  hex(offset))
        super(IndexRecordHeader, self).__init__(buf, offset, parent)
        self.declare_field("dword", "magic", 0x0)
        self.declare_field("word",  "usa_offset")
        self.declare_field("word",  "usa_count")
        self.declare_field("qword", "lsn")
        self.declare_field("qword", "vcn")
        self._node_header_offset = self.current_field_offset()
        self.fixup(self.usa_count(), self.usa_offset())

    def node_header(self):
        return NTATTR_STANDARD_INDEX_HEADER(self._buf,
                               self.offset() + self._node_header_offset,
                               self)


class INDEX_ALLOCATION(FixupBlock):
    def __init__(self, buf, offset, parent):
        """

        TODO(wb): figure out what we're doing with the fixups!

        """
        super(INDEX_ALLOCATION, self).__init__(buf, offset, parent)
        self.declare_field("dword", "magic", 0x0)
        self.declare_field("word",  "usa_offset")
        self.declare_field("word",  "usa_count")
        self.declare_field("qword", "lsn")
        self.declare_field("qword", "vcn")
        self._index_offset = self.current_field_offset()
        self.add_explicit_field(self._index_offset, INDEX, "index")
        # TODO(wb): we do not want to modify data here.
        #   best to make a copy and use that.
        #   Until then, this is not a nestable structure.
        self.fixup(self.usa_count(), self.usa_offset())

    def index(self):
        return INDEX(self._buf, self.offset(self._index_offset),
                     self, MFT_INDEX_ENTRY)

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0x30 + INDEX.structure_size(buf, offset + 0x10, parent)

    def __len__(self):
        return 0x30 + len(self.index())



class IndexEntry(Block):
    def __init__(self, buf, offset, parent):
        logging.debug("INDEX ENTRY at %s.", hex(offset))
        super(IndexEntry, self).__init__(buf, offset)
        self.declare_field("qword", "mft_reference", 0x0)
        self.declare_field("word", "length")
        self.declare_field("word", "filename_information_length")
        self.declare_field("dword", "flags")
        self.declare_field("binary", "filename_information_buffer", \
                           self.current_field_offset(),
                           self.filename_information_length())
        self.declare_field("qword", "child_vcn",
                           align(self.current_field_offset(), 0x8))

    def filename_information(self):
        return FilenameAttribute(self._buf,
                                 self.offset() + self._off_filename_information_buffer,
                                 self)


class StandardInformationFieldDoesNotExist(Exception):
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return "Standard Information attribute field does not exist: %s" % (self._msg)


class StandardInformation(Block):
    # TODO(wb): implement sizing so we can make this nestable
    def __init__(self, buf, offset, parent):
        logging.debug("STANDARD INFORMATION ATTRIBUTE at %s.", hex(offset))
        super(StandardInformation, self).__init__(buf, offset)
        self.declare_field("filetime", "created_time", 0x0)
        self.declare_field("filetime", "modified_time")
        self.declare_field("filetime", "changed_time")
        self.declare_field("filetime", "accessed_time")
        self.declare_field("dword", "attributes")
        self.declare_field("binary", "reserved", self.current_field_offset(), 0xC)
        # self.declare_field("dword", "owner_id", 0x30)  # Win2k+, NTFS 3.x
        # self.declare_field("dword", "security_id")  # Win2k+, NTFS 3.x
        # self.declare_field("qword", "quota_charged")  # Win2k+, NTFS 3.x
        # self.declare_field("qword", "usn")  # Win2k+, NTFS 3.x

    # Can't implement this unless we know the NTFS version in use
    #@staticmethod
    #def structure_size(buf, offset, parent):
    #    return 0x42 + (read_byte(buf, offset + 0x40) * 2)

    # Can't implement this unless we know the NTFS version in use
    #def __len__(self):
    #    return 0x42 + (self.filename_length() * 2)

    def owner_id(self):
        """
        This is an explicit method because it may not exist in OSes under Win2k

        @raises StandardInformationFieldDoesNotExist
        """
        try:
            return self.unpack_dword(0x30)
        except OverrunBufferException:
            raise StandardInformationFieldDoesNotExist("Owner ID")

    def security_id(self):
        """
        This is an explicit method because it may not exist in OSes under Win2k

        @raises StandardInformationFieldDoesNotExist
        """
        try:
            return self.unpack_dword(0x34)
        except OverrunBufferException:
            raise StandardInformationFieldDoesNotExist("Security ID")

    def quota_charged(self):
        """
        This is an explicit method because it may not exist in OSes under Win2k

        @raises StandardInformationFieldDoesNotExist
        """
        try:
            return self.unpack_dword(0x38)
        except OverrunBufferException:
            raise StandardInformationFieldDoesNotExist("Quota Charged")

    def usn(self):
        """
        This is an explicit method because it may not exist in OSes under Win2k

        @raises StandardInformationFieldDoesNotExist
        """
        try:
            return self.unpack_dword(0x40)
        except OverrunBufferException:
            raise StandardInformationFieldDoesNotExist("USN")


class FilenameAttribute(Block, Nestable):
    def __init__(self, buf, offset, parent):
        logging.debug("FILENAME ATTRIBUTE at %s.", hex(offset))
        super(FilenameAttribute, self).__init__(buf, offset)
        self.declare_field("qword", "mft_parent_reference", 0x0)
        self.declare_field("filetime", "created_time")
        self.declare_field("filetime", "modified_time")
        self.declare_field("filetime", "changed_time")
        self.declare_field("filetime", "accessed_time")
        self.declare_field("qword", "physical_size")
        self.declare_field("qword", "logical_size")
        self.declare_field("dword", "flags")
        self.declare_field("dword", "reparse_value")
        self.declare_field("byte", "filename_length")
        self.declare_field("byte", "filename_type")
        self.declare_field("wstring", "filename", 0x42, self.filename_length())

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0x42 + (read_byte(buf, offset + 0x40) * 2)

    def __len__(self):
        return 0x42 + (self.filename_length() * 2)


class SlackIndexEntry(IndexEntry):
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing NTFS INDX file
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent NTATTR_STANDARD_INDEX_HEADER block,
            which links to this block.
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


class Runentry(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(Runentry, self).__init__(buf, offset)
        logging.debug("RUNENTRY @ %s.", hex(offset))
        self.declare_field("byte", "header")
        self._offset_length = self.header() >> 4
        self._length_length = self.header() & 0x0F
        self.declare_field("binary",
                           "length_binary",
                           self.current_field_offset(), self._length_length)
        self.declare_field("binary",
                           "offset_binary",
                           self.current_field_offset(), self._offset_length)

    @staticmethod
    def structure_size(buf, offset, parent):
        b = read_byte(buf, offset)
        return (b >> 4) + (b & 0x0F) + 1

    def __len__(self):
        return 0x1 + (self._length_length + self._offset_length)

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
        # TODO(wb): make this run_offset
        return self.lsb2signednum(self.offset_binary())

    def length(self):
        # TODO(wb): make this run_offset
        return self.lsb2num(self.length_binary())


class Runlist(Block):
    def __init__(self, buf, offset, parent):
        super(Runlist, self).__init__(buf, offset)
        logging.debug("RUNLIST @ %s.", hex(offset))

    @staticmethod
    def structure_size(buf, offset, parent):
        length = 0
        while True:
            b = read_byte(buf, offset + length)
            length += 1
            if b == 0:
                return length

            length += (b >> 4) + (b & 0x0F)

    def __len__(self):
        return sum(map(len, self._entries()))

    def _entries(self, length=None):
        ret = []
        offset = self.offset()
        entry = Runentry(self._buf, offset, self)
        while entry.header() != 0 and \
              (not length or offset < self.offset() + length) and \
              entry.is_valid():
            ret.append(entry)
            offset += len(entry)
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


class Attribute(Block, Nestable):
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
        256: "$LOGGED UTILITY STREAM",
    }

    FLAGS = {
        0x01: "readonly",
        0x02: "hidden",
        0x04: "system",
        0x08: "unused-dos",
        0x10: "directory-dos",
        0x20: "archive",
        0x40: "device",
        0x80: "normal",
        0x100: "temporary",
        0x200: "sparse",
        0x400: "reparse-point",
        0x800: "compressed",
        0x1000: "offline",
        0x2000: "not-indexed",
        0x4000: "encrypted",
        0x10000000: "has-indx",
        0x20000000: "has-view-index",
        }

    def __init__(self, buf, offset, parent):
        super(Attribute, self).__init__(buf, offset)
        logging.debug("ATTRIBUTE @ %s.", hex(offset))
        self.declare_field("dword", "type")
        self.declare_field("dword", "size")  # this value must rounded up to 0x8 byte alignment
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
            self.declare_field("binary", "value",
                               self.value_offset(), self.value_length())

    @staticmethod
    def structure_size(buf, offset, parent):
        s = read_dword(buf, offset + 0x4)
        return s + (8 - (s % 8))

    def __len__(self):
        return self.size()

    def runlist(self):
        return Runlist(self._buf, self.offset() + self.runlist_offset(), self)

    def size(self):
        s = self.unpack_dword(self._off_size)
        return s + (8 - (s % 8))

    def name(self):
        return self.unpack_wstring(self.name_offset(), self.name_length())


class MFT_RECORD_FLAGS:
    MFT_RECORD_IN_USE = 0x1
    MFT_RECORD_IS_DIRECTORY = 0x2


def MREF(mft_reference):
    """
    Given a MREF/mft_reference, return the record number part.
    """
    return mft_reference & 0xFFFFFFFFFFFF


def MSEQNO(mft_reference):
    """
    Given a MREF/mft_reference, return the sequence number part.
    """
    return (mft_reference >> 48) & 0xFFFF


class MFTRecord(FixupBlock):
    """
    Implementation note: cannot be nestable due to fixups.
    """
    def __init__(self, buf, offset, parent, inode=None):
        super(MFTRecord, self).__init__(buf, offset, parent)
        logging.debug("MFTRECORD @ %s.", hex(offset))

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
        self.inode = inode or self.mft_record_number()

        self.fixup(self.usa_count(), self.usa_offset())

    def attributes(self):
        offset = self.attrs_offset()

        while self.unpack_dword(offset) != 0 and \
              self.unpack_dword(offset) != 0xFFFFFFFF and \
              offset + self.unpack_dword(offset + 4) <= self.offset() + self.bytes_in_use():
            a = Attribute(self._buf, offset, self)
            offset += len(a)
            yield a

    def attribute(self, attr_type):
        for a in self.attributes():
            if a.type() == attr_type:
                return a

    def is_directory(self):
        return self.flags() & MFT_RECORD_FLAGS.MFT_RECORD_IS_DIRECTORY

    def is_active(self):
        return self.flags() & MFT_RECORD_FLAGS.MFT_RECORD_IN_USE

    # this a required resident attribute
    def filename_information(self):
        """
        MFT Records may have more than one FN info attribute,
        each with a different type of filename (8.3, POSIX, etc.)

        This function returns the attribute with the most complete name,
          that is, it tends towards Win32, then POSIX, and then 8.3.
        """
        fn = None
        for a in self.attributes():
            # TODO optimize to self._buf here
            if a.type() == ATTR_TYPE.FILENAME_INFORMATION:
                try:
                    value = a.value()
                    check = FilenameAttribute(value, 0, self)
                    if check.filename_type() == 0x0001 or \
                       check.filename_type() == 0x0003:
                        return check
                    fn = check
                except Exception:
                    pass
        return fn

    # this a required resident attribute
    def standard_information(self):
        try:
            attr = self.attribute(ATTR_TYPE.STANDARD_INFORMATION)
            return StandardInformation(attr.value(), 0, self)
        except AttributeError:
            return None

    def data_attribute(self):
        """
        Returns None if the default $DATA attribute does not exist
        """
        for attr in self.attributes():
            if attr.type() == ATTR_TYPE.DATA and attr.name() == "":
                return attr

    def slack_data(self):
        """
        Returns A binary string containing the MFT record slack.
        """
        return self._buf[self.offset()+self.bytes_in_use():self.offset() + 1024].tostring()

    def active_data(self):
        """
        Returns A binary string containing the MFT record slack.
        """
        return self._buf[self.offset():self.offset() + self.bytes_in_use()].tostring()


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
            f.seek(0x30, 1)  # relative
            buf = f.read(8)
            relmftoffset = struct.unpack_from("<Q", buf, 0)[0]
            self.mftoffset = self.offset + relmftoffset * self.clustersize
            logging.debug("MFT offset is %s", hex(self.mftoffset))

    def record_generator(self, start_at=0):
        """
        @type start_at: int
        @param start_at: the inode number to start at
        @rtype generator of MFTRecord
        """
        if self.filetype == "indx":
            return
        if self.filetype == "mft":
            size = os.path.getsize(self.filename)
            is_redirected = os.fstat(0) != os.fstat(1)
            should_progress = is_redirected and self.progress
            with open(self.filename, "rb") as f:
                record = True
                count = start_at - 1
                f.seek(start_at * 1024, 0)
                while record:
                    # TODO(wb): this really shouldn't be here
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
                        logging.debug("Failed to parse MFT record %s", str(count))
                        continue
                    logging.debug("Yielding record %d", count)
                    yield record
            if should_progress:
                sys.stderr.write("\n")
        if self.filetype == "image":
            # TODO this overruns the MFT...
            # TODO this doesnt account for a fragmented MFT
            with open(self.filename, "rb") as f:
                if not self.mftoffset:
                    self._calculate_mftoffset()
                f.seek(self.mftoffset + (start_at * 1024))
                record = True
                count = start_at - 1
                while record:
                    count += 1
                    buf = array.array("B", f.read(1024))
                    if not buf:
                        return
                    try:
                        record = MFTRecord(buf, 0, False, inode=count)
                    except OverrunBufferException:
                        logging.debug("Failed to parse MFT record %s", str(count))
                        continue
                    logging.debug("Yielding record %d", count)
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
        if cycledetector is None:
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
            logging.debug("Cycle detected")
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


class InvalidAttributeException(INDXException):
    def __init__(self, value):
        super(InvalidAttributeException, self).__init__(value)

    def __str__(self):
        return "Invalid attribute Exception(%s)" % (self._value)


class InvalidMFTRecordNumber(Exception):
    def __init__(self, value):
        self.value = value


class MFTOperationNotImplementedError(Exception):
    def __init__(self, msg):
        super(MFTOperationNotImplementedError, self).__init__(msg)
        self._msg = msg

    def __str__(self):
        return "MFTOperationNotImplemented(%s)" % (self._msg)


class InvalidRecordException(Exception):
    def __init__(self, msg):
        super(InvalidRecordException, self).__init__(msg)
        self._msg = msg

    def __str__(self):
        return "InvalidRecordException(%s)" % (self._msg)


class Cache(object):
    def __init__(self, size_limit):
        super(Cache, self).__init__()
        self._c = OrderedDict()
        self._size_limit = size_limit

    def insert(self, k, v):
        """
        add a key and value to the front
        """
        self._c[k] = v
        if len(self._c) > self._size_limit:
            self._c.popitem(last=False)

    def exists(self, k):
        return k in self._c

    def touch(self, k):
        """
        bring a key to the front
        """
        v = self._c[k]
        del self._c[k]
        self._c[k] = v

    def get(self, k):
        return self._c[k]


MFT_RECORD_SIZE = 1024
FILE_SEP = "\\"
UNKNOWN_ENTRY = "??"
ORPHAN_ENTRY = "$ORPHAN"
CYCLE_ENTRY = "<CYCLE>"


class MFTEnumerator(object):
    def __init__(self, buf, record_cache=None, path_cache=None):
        DEFAULT_CACHE_SIZE = 1024
        if record_cache is None:
            record_cache = Cache(size_limit=DEFAULT_CACHE_SIZE)
        if path_cache is None:
            path_cache = Cache(size_limit=DEFAULT_CACHE_SIZE)

        self._buf = buf
        self._record_cache = record_cache
        self._path_cache = path_cache

    def len(self):
        return len(self._buf) / MFT_RECORD_SIZE

    def get_record_buf(self, record_num):
        """
        @raises OverrunBufferException: if the record_num is beyond the end of the MFT
        """
        start = record_num * MFT_RECORD_SIZE
        end = start + MFT_RECORD_SIZE
        if end > len(self._buf):
            raise OverrunBufferException(end, len(self._buf))

        return array.array("B", self._buf[start:end])

    def get_record(self, record_num):
        """
        @raises OverrunBufferException: if the record_num is beyond the end of the MFT.
        @raises InvalidRecordException: if the record appears invalid (incorrect magic header).
        """
        if self._record_cache.exists(record_num):
            self._record_cache.touch(record_num)
            return self._record_cache.get(record_num)


        record_buf = self.get_record_buf(record_num)
        if read_dword(record_buf, 0x0) != 0x454C4946:
            raise InvalidRecordException("record_num: %d" % record_num)

        record = MFTRecord(record_buf, 0, False, inode=record_num)
        self._record_cache.insert(record_num, record)
        return record

    def enumerate_records(self):
        index = 0
        while True:
            if index == 12:  # reserved records are 12-15
                index = 16
            try:
                record = self.get_record(index)
                yield record
                index += 1
            except OverrunBufferException:
                return
            except InvalidRecordException:
                index += 1
                continue

    def enumerate_paths(self):
        for record in self.enumerate_records():
            path = self.get_path(record)
            yield record, path

    def get_path(self, record):
        """
        @type record: MFTRecord
        @rtype: str
        @return: A string containing the path of the given record. It will begin with the first
          path component, that is, something like "Documents and Settings\Adminstrator\bad.exe".
          In the event that a path component cannot be determined, it is replaced by "??".
          If the parent of an entry cannot be verified, then it is added to the $ORPHAN directory.
          If a cycle is detected during the path resolution, then the offending entry is
            replaced with <CYCLE>. This occastionally happens at the root directory.
        """
        return self._get_path_impl(record, set())

    def _get_path_impl(self, record, cycledetector):
        """
        @type cycledetector: set of int
        @param cycledetector: A set of numbers that describe which records have been processed
          in the building of the path.
        """
        key = "%d-%d-%d-%d-%d" % (record.magic(), record.lsn(),
                                  record.link_count(), record.mft_record_number(),
                                  record.flags())
        if self._path_cache.exists(key):
            self._path_cache.touch(key)
            return self._path_cache.get(key)

        record_num = record.mft_record_number()
        if record_num == 5:
            return ""

        if record_num in cycledetector:
            return CYCLE_ENTRY
        cycledetector.add(record_num)

        fn = record.filename_information()

        if not fn:
            return UNKNOWN_ENTRY
        else:
            record_filename = fn.filename()

        parent_record_num = MREF(fn.mft_parent_reference())
        parent_seq_num = MSEQNO(fn.mft_parent_reference())

        try:
            parent_record = self.get_record(parent_record_num)
        except (OverrunBufferException, InvalidRecordException):
            return ORPHAN_ENTRY + FILE_SEP + record_filename

        if parent_record.sequence_number() != parent_seq_num:
            return ORPHAN_ENTRY + FILE_SEP + record_filename

        path = self._get_path_impl(parent_record, cycledetector) + FILE_SEP + record_filename
        self._path_cache.insert(key, path)
        return path

    def get_record_by_path(self, path):
        lower_path = path.lower()
        for record, record_path in self.enumerate_paths():
            if lower_path == record_path.lower():
                return record
        raise KeyError("Path not found: " % path)


class MFTTreeNode(object):
    def __init__(self, nodes, record_number, filename, parent_record_number):
        super(MFTTreeNode, self).__init__()
        self._nodes = nodes
        self._record_number = record_number
        self._filename = filename
        self._parent_record_number = parent_record_number
        self._children_record_numbers = []

    def get_record_number(self):
        return self._record_number

    def get_filename(self):
        return self._filename

    def get_parent(self):
        return self._nodes[self._parent_record_number]

    def add_child_record_number(self, child_record_number):
        self._children_record_numbers.append(child_record_number)

    def get_children_nodes(self):
        return map(lambda n: self._nodes[n], self._children_record_numbers)

    def get_child_node(self, filename):
        for child in self.get_children_nodes():
            if child.get_filename() == filename:
                return child
        raise KeyError("Failed to find filename: " + filename)


ROOT_INDEX = 5
class MFTTree(object):
    ORPHAN_INDEX = 12

    def __init__(self, buf):
        super(MFTTree, self).__init__()
        self._buf = buf
        self._nodes = {}  # array of MFTTreeNodes

    def _add_record(self, mft_enumerator, record):
        record_num = record.mft_record_number()

        if record_num in self._nodes:
            return

        if record_num == ROOT_INDEX:
            self._nodes[ROOT_INDEX] = MFTTreeNode(self._nodes, ROOT_INDEX, "\.", ROOT_INDEX)
            return

        fn = record.filename_information()
        if not fn:
            # then there's no filename, or parent reference
            # there could be some standard information (timestamps),
            # or named streams
            # but still no parent link.
            # ...so lets bail
            return

        parent_record_num = MREF(fn.mft_parent_reference())
        parent_seq_num = MSEQNO(fn.mft_parent_reference())

        try:
            parent_record = mft_enumerator.get_record(parent_record_num)
        except (OverrunBufferException, InvalidRecordException):
            parent_record_num = MFTTree.ORPHAN_INDEX
            parent_record = None

        if not parent_record:
            parent_record_num = MFTTree.ORPHAN_INDEX
        elif parent_record.sequence_number() != parent_seq_num:
            parent_record_num = MFTTree.ORPHAN_INDEX

        if parent_record_num != MFTTree.ORPHAN_INDEX and parent_record:
            self._add_record(mft_enumerator, parent_record)

        try:
            parent_node = self._nodes[parent_record_num]
        except IndexError:
            parent_record_num = MFTTree.ORPHAN_INDEX

        record_node = MFTTreeNode(self._nodes, record_num, fn.filename(), parent_record_num)
        self._nodes[record_num] = record_node
        if parent_node:
            parent_node.add_child_record_number(record_num)

    def build(self, record_cache=None,
              path_cache=None, progress_class=NullProgress):
        DEFAULT_CACHE_SIZE = 1024
        if record_cache is None:
            record_cache = Cache(size_limit=DEFAULT_CACHE_SIZE)
        if path_cache is None:
            path_cache = Cache(size_limit=DEFAULT_CACHE_SIZE)

        enum = MFTEnumerator(self._buf, record_cache=record_cache, path_cache=path_cache)

        self._nodes[MFTTree.ORPHAN_INDEX] = MFTTreeNode(self._nodes, MFTTree.ORPHAN_INDEX,
                                                        ORPHAN_ENTRY, ROOT_INDEX)

        count = 0
        progress = progress_class(len(self._buf) / 1024)
        for record in enum.enumerate_records():
            self._add_record(enum, record)
            count += 1
            progress.set_current(count)
        progress.set_complete()

    def get_root(self):
        return self._nodes[ROOT_INDEX]

#!/bin/python

#    This file is part of INDXParse.
#
#   Copyright 2011-13 Will Ballenthin <william.ballenthin@mandiant.com>
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
#   Version v.1.2
from BinaryParser import Block
from BinaryParser import Nestable
from BinaryParser import ParseException
from BinaryParser import align
from BinaryParser import read_byte
from BinaryParser import read_word
from BinaryParser import read_dword


class NULL_OBJECT(object):
    def __init__(self):
        super(NULL_OBJECT, self).__init__()

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0

    def __len__(self):
        return 0

null_object = NULL_OBJECT()


class SECURITY_DESCRIPTOR_CONTROL:
    SE_OWNER_DEFAULTED = 1 << 0
    SE_GROUP_DEFAULTED = 1 << 1
    SE_DACL_PRESENT = 1 << 2
    SE_DACL_DEFAULTED = 1 << 3
    SE_SACL_PRESENT = 1 << 4
    SE_SACL_DEFAULTED = 1 << 5
    SE_SACL_UNUSED0 = 1 << 6
    SE_SACL_UNUSED1 = 1 << 7
    SE_DACL_AUTO_INHERIT_REQ = 1 << 8
    SE_SACL_AUTO_INHERIT_REQ = 1 << 9
    SE_DACL_AUTO_INHERITED = 1 << 10
    SE_SACL_AUTO_INHERITED = 1 << 11
    SE_DACL_PROTECTED = 1 << 12
    SE_SACL_PROTECTED = 1 << 13
    SE_RM_CONTROL_VALID = 1 << 14
    SE_SELF_RELATIVE = 1 << 15


class SID_IDENTIFIER_AUTHORITY(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(SID_IDENTIFIER_AUTHORITY, self).__init__(buf, offset)
        self.declare_field("word_be", "high_part", 0x0)
        self.declare_field("dword_be", "low_part")

    @staticmethod
    def structure_size(buf, offset, parent):
        return 6

    def __len__(self):
        return SID_IDENTIFIER_AUTHORITY.structure_size(self._buf, self.absolute_offset(0x0), None)

    def __str__(self):
        return "%s" % (self.high_part() << 32 + self.low_part())


class SID(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(SID, self).__init__(buf, offset)
        self.declare_field("byte", "revision", 0x0)
        self.declare_field("byte", "sub_authority_count")
        self.declare_field(SID_IDENTIFIER_AUTHORITY, "identifier_authority")
        self.declare_field("dword", "sub_authorities", count=self.sub_authority_count())

    @staticmethod
    def structure_size(buf, offset, parent):
        sub_auth_count = read_byte(buf, offset + 1)
        auth_size = SID_IDENTIFIER_AUTHORITY.structure_size(buf, offset + 2, parent)
        return 2 + auth_size + (sub_auth_count * 4)

    def __len__(self):
        return self._off_sub_authorities + (self.sub_authority_count() * 4)

    def string(self):
        ret = "S-%d-%s" % (self.revision(), self.identifier_authority())
        for sub_auth in self.sub_authorities():
            ret += "-%s" % (str(sub_auth))
        return ret


class ACE_TYPES:
    """
    One byte.
    """
    ACCESS_MIN_MS_ACE_TYPE = 0
    ACCESS_ALLOWED_ACE_TYPE = 0
    ACCESS_DENIED_ACE_TYPE = 1
    SYSTEM_AUDIT_ACE_TYPE = 2
    SYSTEM_ALARM_ACE_TYPE = 3  # Not implemented as of Win2k.
    ACCESS_MAX_MS_V2_ACE_TYPE = 3

    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 4
    ACCESS_MAX_MS_V3_ACE_TYPE = 4

    # The following are Win2k only.
    ACCESS_MIN_MS_OBJECT_ACE_TYPE = 5
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 5
    ACCESS_DENIED_OBJECT_ACE_TYPE = 6
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 7
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 8
    ACCESS_MAX_MS_OBJECT_ACE_TYPE = 8
    ACCESS_MAX_MS_V4_ACE_TYPE = 8

    # This one is for WinNT/2k.
    ACCESS_MAX_MS_ACE_TYPE = 8


class ACE_FLAGS:
    """
    One byte.
    """
    OBJECT_INHERIT_ACE = 0x01
    CONTAINER_INHERIT_ACE = 0x02
    NO_PROPAGATE_INHERIT_ACE = 0x04
    INHERIT_ONLY_ACE = 0x08
    INHERITED_ACE = 0x10  # Win2k only.
    VALID_INHERIT_FLAGS = 0x1f

    # The audit flags.
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
    FAILED_ACCESS_ACE_FLAG = 0x80


class ACCESS_MASK:
    """
    DWORD.
    """
    FILE_READ_DATA = 0x00000001
    FILE_LIST_DIRECTORY = 0x00000001
    FILE_WRITE_DATA = 0x00000002
    FILE_ADD_FILE = 0x00000002
    FILE_APPEND_DATA = 0x00000004
    FILE_ADD_SUBDIRECTORY = 0x00000004
    FILE_READ_EA = 0x00000008
    FILE_WRITE_EA = 0x00000010
    FILE_EXECUTE = 0x00000020
    FILE_TRAVERSE = 0x00000020
    FILE_DELETE_CHILD = 0x00000040
    FILE_READ_ATTRIBUTES = 0x00000080
    FILE_WRITE_ATTRIBUTES = 0x00000100
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000
    STANDARD_RIGHTS_READ = 0x00020000
    STANDARD_RIGHTS_WRITE = 0x00020000
    STANDARD_RIGHTS_EXECUTE = 0x00020000
    STANDARD_RIGHTS_REQUIRED = 0x000f0000
    STANDARD_RIGHTS_ALL = 0x001f0000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    MAXIMUM_ALLOWED = 0x02000000
    GENERIC_ALL = 0x10000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000


class ACE(Block):
    def __init__(self, buf, offset, parent):
        super(ACE, self).__init__(buf, offset)
        self.declare_field("byte", "ace_type", 0x0)
        self.declare_field("byte", "ace_flags")

    @staticmethod
    def get_ace(buf, offset, parent):
        header = ACE(buf, offset, parent)
        if header.ace_type() == ACE_TYPES.ACCESS_ALLOWED_ACE_TYPE:
            return ACCESS_ALLOWED_ACE(buf, offset, parent)
        elif header.ace_type() == ACE_TYPES.ACCESS_DENIED_ACE_TYPE:
            return ACCESS_DENIED_ACE(buf, offset, parent)
        elif header.ace_type() == ACE_TYPES.SYSTEM_AUDIT_ACE_TYPE:
            return SYSTEM_AUDIT_ACE(buf, offset, parent)
        elif header.ace_type() == ACE_TYPES.SYSTEM_ALARM_ACE_TYPE:
            return SYSTEM_ALARM_ACE(buf, offset, parent)
        elif header.ace_type() == ACE_TYPES.ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            return ACCESS_ALLOWED_OBJECT_ACE(buf, offset, parent)
        elif header.ace_type() == ACE_TYPES.ACCESS_DENIED_OBJECT_ACE_TYPE:
            return ACCESS_DENIED_OBJECT_ACE(buf, offset, parent)
        elif header.ace_type() == ACE_TYPES.SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            return SYSTEM_AUDIT_OBJECT_ACE(buf, offset, parent)
        elif header.ace_type() == ACE_TYPES.SYSTEM_ALARM_OBJECT_ACE_TYPE:
            return SYSTEM_ALARM_OBJECT_ACE(buf, offset, parent)
        else:
            raise ParseException("unknown ACE type")


class StandardACE(ACE, Nestable):
    def __init__(self, buf, offset, parent):
        super(StandardACE, self).__init__(buf, offset, parent)
        self.declare_field("word", "size", 0x2)
        self.declare_field("dword", "access_mask")
        self.declare_field(SID, "sid")

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_word(buf, offset + 0x2)

    def __len__(self):
        return self.size()


class ACCESS_ALLOWED_ACE(StandardACE):
    def __init__(self, buf, offset, parent):
        super(ACCESS_ALLOWED_ACE, self).__init__(buf, offset, parent)


class ACCESS_DENIED_ACE(StandardACE):
    def __init__(self, buf, offset, parent):
        super(ACCESS_DENIED_ACE, self).__init__(buf, offset, parent)


class SYSTEM_AUDIT_ACE(StandardACE):
    def __init__(self, buf, offset, parent):
        super(SYSTEM_AUDIT_ACE, self).__init__(buf, offset, parent)


class SYSTEM_ALARM_ACE(StandardACE):
    def __init__(self, buf, offset, parent):
        super(SYSTEM_ALARM_ACE, self).__init__(buf, offset, parent)


class OBJECT_ACE_FLAGS:
    """
    DWORD.
    """
    ACE_OBJECT_TYPE_PRESENT = 1
    ACE_INHERITED_OBJECT_TYPE_PRESENT = 2


class ObjectACE(ACE, Nestable):
    def __init__(self, buf, offset, parent):
        super(ObjectACE, self).__init__(buf, offset, parent)
        self.declare_field("word", "size", 0x2)
        self.declare_field("dword", "access_mask")
        self.declare_field("dword", "object_flags")
        self.declare_field("guid", "object_type")
        self.declare_field("guid", "inherited_object_type")

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_word(buf, offset + 0x2)

    def __len__(self):
        return self.size()


class ACCESS_ALLOWED_OBJECT_ACE(ObjectACE):
    def __init__(self, buf, offset, parent):
        super(ACCESS_ALLOWED_OBJECT_ACE, self).__init__(buf, offset, parent)


class ACCESS_DENIED_OBJECT_ACE(ObjectACE):
    def __init__(self, buf, offset, parent):
        super(ACCESS_DENIED_OBJECT_ACE, self).__init__(buf, offset, parent)


class SYSTEM_AUDIT_OBJECT_ACE(ObjectACE):
    def __init__(self, buf, offset, parent):
        super(SYSTEM_AUDIT_OBJECT_ACE, self).__init__(buf, offset, parent)


class SYSTEM_ALARM_OBJECT_ACE(ObjectACE):
    def __init__(self, buf, offset, parent):
        super(SYSTEM_ALARM_OBJECT_ACE, self).__init__(buf, offset, parent)


class ACL(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(ACL, self).__init__(buf, offset)
        self.declare_field("byte", "revision", 0x0)
        self.declare_field("byte", "alignment1")
        self.declare_field("word", "size")
        self.declare_field("word", "ace_count")
        self.declare_field("word", "alignment2")
        self._off_ACEs = self.current_field_offset()
        self.add_explicit_field(self._off_ACEs, ACE, "ACEs")

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_word(buf, offset + 0x2)

    def __len__(self):
        return self.size()

    def ACEs(self):
        ofs = self._off_ACEs
        for _ in range(self.ace_count()):
            a = ACE.get_ace(self._buf, self.offset() + ofs, self)
            yield a
            ofs += a.size()
            ofs = align(ofs, 4)


class NULL_ACL(object):
    """
    TODO(wb): Not actually sure what the NULL ACL is...
      just guessing at the values here.
    """
    def __init__(self):
        super(NULL_ACL, self).__init__()

    def revision(self):
        return 1

    def alignment1(self):
        return 0

    def size(self):
        return 0

    def ace_count(self):
        return 0

    def ACEs(self):
        return

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0

    def __len__(self):
        return 0


class SECURITY_DESCRIPTOR_RELATIVE(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(SECURITY_DESCRIPTOR_RELATIVE, self).__init__(buf, offset)
        self.declare_field("byte", "revision", 0x0)
        self.declare_field("byte", "alignment")
        self.declare_field("word", "control")
        self.declare_field("dword", "owner_offset")
        self.declare_field("dword", "group_offset")
        self.declare_field("dword", "sacl_offset")
        self.declare_field("dword", "dacl_offset")

        self.add_explicit_field(self.owner_offset(), "SID", "owner")
        self.add_explicit_field(self.group_offset(), "SID", "group")
        if self.control() & SECURITY_DESCRIPTOR_CONTROL.SE_SACL_PRESENT:
            self.add_explicit_field(self.sacl_offset(), "ACL", "sacl")
        if self.control() & SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT:
            self.add_explicit_field(self.dacl_offset(), "ACL", "dacl")

    @staticmethod
    def structure_size(buf, offset, parent):
        return len(SECURITY_DESCRIPTOR_RELATIVE(buf, offset, parent))

    def __len__(self):
        ret = 20
        ret += len((self.owner() or null_object))
        ret += len((self.group() or null_object))
        ret += len((self.sacl() or null_object))
        ret += len((self.dacl() or null_object))
        return ret

    def owner(self):
        if self.owner_offset() != 0:
            return SID(self._buf, self.absolute_offset(self.owner_offset()), self)
        else:
            return None

    def group(self):
        if self.group_offset() != 0:
            return SID(self._buf, self.absolute_offset(self.group_offset()), self)
        else:
            return None

    def sacl(self):
        if self.control() & SECURITY_DESCRIPTOR_CONTROL.SE_SACL_PRESENT:
            if self.sacl_offset() > 0:
                return ACL(self._buf, self.absolute_offset(self.sacl_offset()), self)
            else:
                return NULL_ACL()
        else:
            return None

    def dacl(self):
        if self.control() & SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT:
            if self.dacl_offset() > 0:
                return ACL(self._buf, self.absolute_offset(self.dacl_offset()), self)
            else:
                return NULL_ACL()
        else:
            return None


class SDS_ENTRY(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(SDS_ENTRY, self).__init__(buf, offset)
        self.declare_field("dword", "hash", 0x0)
        self.declare_field("dword", "security_id")
        self.declare_field("qword", "offset")
        self.declare_field("dword", "length")
        self.declare_field(SECURITY_DESCRIPTOR_RELATIVE, "sid")

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_dword(buf, offset + 0x10)

    def __len__(self):
        return self.length()


class SDS(Block):
    def __init__(self, buf, offset, parent):
        super(SDS, self).__init__(buf, offset)
        self.add_explicit_field(0, SDS, "sds_entries")

    def sds_entries(self):
        ofs = 0
        while len(self._buf) > self.offset() + ofs + 0x14:
            s = SDS_ENTRY(self._buf, self.offset() + ofs, self)
            if len(s) != 0:
                yield s
                ofs += len(s)
                ofs = align(ofs, 0x10)
            else:
                if ofs % 0x10000 == 0:
                    return
                else:
                    ofs = align(ofs, 0x10000)


def main():
    import sys
    import mmap
    import contextlib

    with open(sys.argv[1], 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            s = SDS(buf, 0, None)
            print "SDS"
            for e in s.sds_entries():
                print("  SDS_ENTRY")
                print(e.get_all_string(indent=2))

if __name__ == "__main__":
    main()

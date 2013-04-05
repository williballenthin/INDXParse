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
#   Version v.1.2
from BinaryParser import Block
from BinaryParser import read_byte
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


class ACL(Block):
    def __init__(self, buf, offset, parent):
        super(ACL, self).__init__(buf, offset)
        self.declare_field("byte", "revision", 0x0)
        self.declare_field("byte", "alignment1")
        self.declare_field("word", "size")
        self.declare_field("word", "ace_count")
        self.declare_field("word", "alignment2")
        # TODO(wb): ACEs
        # http://www.cs.fsu.edu/~baker/devices/lxr/http/source/linux/fs/ntfs/layout.h#L1354

    @staticmethod
    def structure_size(buf, offset, parent):
        return 8

    def __len__(self):
        return ACL.structure_size(self._buf, self.absolute_offset(0x0), None)


class NULL_ACL(object):
    """
    TODO(wb): Not actually sure what the NULL ACL is...
      just guessing at the values here.
    """
    def __init__(self):
        super(NULL_ACL, self).__init__(self)

    def revision(self):
        return 1

    def alignment1(self):
        return 0

    def size(self):
        return 0

    def ace_count(self):
        return 0

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0

    def __len__(self):
        return 0


class SID_IDENTIFIER_AUTHORITY(Block):
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


class SID(Block):
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


class SECURITY_DESCRIPTOR_RELATIVE(Block):
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
        self.add_explicit_field(self.owner_offset(), "SID", "group")
        if self.control() & SECURITY_DESCRIPTOR_CONTROL.SE_SACL_PRESENT:
            self.add_explicit_field(self.sacl_offset(), "ACL", "sacl")
        if self.control() & SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT:
            self.add_explicit_field(self.dacl_offset(), "ACL", "dacl")

    # no `structure_size`, since it would be no better than parsing out the object fully

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


class SDS_ENTRY(Block):
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


def main():
    import sys
    import mmap
    import contextlib

    with open(sys.argv[1], 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            e = SDS_ENTRY(buf, 0, None)
            print("SDS_ENTRY")
            print(e.get_all_string(indent=1))

if __name__ == "__main__":
    main()

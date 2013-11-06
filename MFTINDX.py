#!/usr/bin/python

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
#   Version v.1.2.0
from MFT import *
from BinaryParser import info
from BinaryParser import warning
from BinaryParser import debug
from BinaryParser import error
import calendar

verbose = False
import argparse


def information_bodyfile(path, size, inode, owner_id, info, attributes=None):
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
    return u"0|%s|%s|0|%d|0|%s|%s|%s|%s|%s\n" % (path + attributes_text, inode,
                                                 owner_id,
                                                 size, accessed, modified,
                                                 changed, created)


def record_bodyfile(ntfsfile, record, inode=None, attributes=None):
    """
    Return a bodyfile formatted string for the given MFT record.
    The string contains metadata for the one file described by the record.
    The string may have multiple lines, which cover $SI and
      $FN timestamp entries, and entries for each ADS.
    """
    ret = ""
    if not attributes:
        attributes = []
    path = ntfsfile.mft_record_build_path(record, {})
    si = record.standard_information()
    fn = record.filename_information()
    if not fn:
        raise InvalidAttributeException("Unable to parse attribute")
    inode = record.inode or record.mft_record_number()
    if record.is_directory():
        size = 0
    else:
        data_attr = record.data_attribute()
        if data_attr and data_attr.non_resident() > 0:
            size = data_attr.data_size()
        else:
            size = fn.logical_size()

    ADSs = []
    for attr in record.attributes():
        if attr.type() != ATTR_TYPE.DATA or len(attr.name()) == 0:
            continue
        if attr.non_resident() > 0:
            size = attr.data_size()
        else:
            size = attr.value_length()
#        sys.stderr.write("|%s, %s|\n" % (attr.name(), len(attr.name())))
        ADSs.append((attr.name(), size))

    if si:
        try:
            si_index = si.security_id()
        except StandardInformationFieldDoesNotExist:
            si_index = 0
        ret += "%s" % (information_bodyfile(path, size, inode, si_index, si, attributes))
        for ads in ADSs:
            ret += "%s" % (information_bodyfile(path + ":" + ads[0],
                                                ads[1], inode, si_index, si, attributes))

#    sys.stderr.write(str(ADSs) + "\n")
    attributes.append("filename")
    if si:
        try:
            si_index = si.security_id()
        except StandardInformationFieldDoesNotExist:
            si_index = 0
        ret += "%s" % (information_bodyfile(path, size, inode, si_index, fn,
                                            attributes=attributes))
        for ads in ADSs:
            ret += "%s" % (information_bodyfile(path + ":" + ads[0], ads[1],
                                                inode, si_index,  fn,
                                                attributes=attributes))

    return ret


def node_header_bodyfile(options, node_header, basepath):
    """
    Returns a bodyfile formatted string for all INDX entries following the
    given INDX node header.
    """
    ret = ""
    attrs = ["filename", "INDX"]
    if options.indxlist:
        for e in node_header.entries():
            path = basepath + "\\" + e.filename_information().filename()
            size = e.filename_information().logical_size()
            inode = 0
            ret += information_bodyfile(path, size, inode, 0,
                                        e.filename_information(),
                                        attributes=attrs)
    attrs.append("slack")
    if options.slack:
        for e in node_header.slack_entries():
            path = basepath + "\\" + e.filename_information().filename()
            size = e.filename_information().logical_size()
            inode = 0
            ret += information_bodyfile(path, size, inode, 0,
                                        e.filename_information(),
                                        attributes=attrs)
    return ret


def record_indx_entries_bodyfile(options, ntfsfile, record):
    """
    Returns a bodyfile formatted string for all INDX entries associated with
    the given MFT record
    """
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
                    ooff = offset * options.clustersize + options.offset
                    llen = length * options.clustersize
                    extractbuf += f.read(ooff,
                                         llen)
                except IOError:
                    pass
        else:
            extractbuf += array.array("B", attr.value())
    if len(extractbuf) < 4096:  # TODO make this INDX record size
        return ret
    offset = 0
    try:
        irh = IndexRecordHeader(extractbuf, offset, False)
    except OverrunBufferException:
        return ret
    # TODO could miss something if there is an empty, valid record at the end
    while irh.magic() == 0x58444E49:
        nh = irh.node_header()
        ret += node_header_bodyfile(options, nh, basepath)
        # TODO get this from the boot record
        offset += options.clustersize
        if offset + 4096 > len(extractbuf):  # TODO make this INDX record size
            return ret
        try:
            irh = IndexRecordHeader(extractbuf, offset, False)
        except OverrunBufferException:
            return ret
    return ret


def try_write(s):
    try:
        sys.stdout.write(s)
    except (UnicodeEncodeError, UnicodeDecodeError):
        warning("Failed to write string "
                "due to encoding issue: " + str(list(s)))


def print_nonresident_indx_bodyfile(options, buf, basepath=""):
    offset = 0
    try:
        irh = IndexRecordHeader(buf, offset, False)
    except OverrunBufferException:
        return
    # TODO could miss something if there is an empty, valid record at the end
    while irh.magic() == 0x58444E49:
        nh = irh.node_header()
        try_write(node_header_bodyfile(options, nh, basepath))
        offset += options.clustersize
        if offset + 4096 > len(buf):  # TODO make this INDX record size
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
                        debug("Skipping listing path "
                              "due to regex filter: " + path)
                        continue
                if record.is_active() and options.mftlist:
                    try_write(record_bodyfile(f, record))
                if options.indxlist or options.slack:
                    try_write(record_indx_entries_bodyfile(options, f, record))
                elif (not record.is_active()) and options.deleted:
                    try_write(record_bodyfile(f, record,
                                              attributes=["deleted"]))
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
                                ooff = offset * options.clustersize + options.offset
                                llen = length * options.clustersize
                                extractbuf += f.read(ooff, llen)
                        else:
                            pass  # This shouldn't happen.
                    if found_indxalloc and len(extractbuf) > 0:
                        path = f.mft_record_build_path(record, {})
                        print_nonresident_indx_bodyfile(options,
                                                        extractbuf,
                                                        basepath=path)
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

    if record.magic() != 0x454c4946:
        if record.magic() == int("0xBAAD", 0x10):
            print "BAAD Record"
        else:
            print "Invalid magic header: ", hex(record.magic())
            return

    print "Path: " + f.mft_record_build_path(record, {})
    print "MFT Record: " + str(record.mft_record_number())

    print "Metadata: "
    if record.is_active():
        print "  active file"
    else:
        print "  deleted file"

    if record.is_directory():
        print "  type: directory"
    else:
        print "  type: file"

    if not record.is_directory():
        data_attr = record.data_attribute()
        if data_attr and data_attr.non_resident() > 0:
            print "  size: %d bytes" % (data_attr.data_size())
        else:
            print "  size: %d bytes" % \
                (record.filename_information().logical_size())

    def get_flags(flags):
        attributes = []
        if flags & 0x01:
            attributes.append("readonly")
        if flags & 0x02:
            attributes.append("hidden")
        if flags & 0x04:
            attributes.append("system")
        if flags & 0x08:
            attributes.append("unused-dos")
        if flags & 0x10:
            attributes.append("directory-dos")
        if flags & 0x20:
            attributes.append("archive")
        if flags & 0x40:
            attributes.append("device")
        if flags & 0x80:
            attributes.append("normal")
        if flags & 0x100:
            attributes.append("temporary")
        if flags & 0x200:
            attributes.append("sparse")
        if flags & 0x400:
            attributes.append("reparse-point")
        if flags & 0x800:
            attributes.append("compressed")
        if flags & 0x1000:
            attributes.append("offline")
        if flags & 0x2000:
            attributes.append("not-indexed")
        if flags & 0x4000:
            attributes.append("encrypted")
        if flags & 0x10000000:
            attributes.append("has-indx")
        if flags & 0x20000000:
            attributes.append("has-view-index")
        return attributes

    print "  attributes: " + \
        ", ".join(get_flags(record.standard_information().attributes()))

    crtime = record.standard_information().created_time().isoformat("T") + "Z"
    mtime = record.standard_information().modified_time().isoformat("T") + "Z"
    chtime = record.standard_information().changed_time().isoformat("T") + "Z"
    atime = record.standard_information().accessed_time().isoformat("T") + "Z"

    print "  SI modified: %s" % (mtime)
    print "  SI accessed: %s" % (atime)
    print "  SI changed: %s" % (chtime)
    print "  SI birthed: %s" % (crtime)

    try:
        # since the fields are sequential, we can handle an exception half way through here
        #  and then ignore the remaining items. Dont have to worry about individual try/catches
        print "  owner id (quota info): %d" % (record.standard_information().owner_id())
        print "  security id: %d" % (record.standard_information().security_id())
        print "  quota charged: %d" % (record.standard_information().quota_charged())
        print "  USN: %d" % (record.standard_information().usn())
    except StandardInformationFieldDoesNotExist:
        pass

    print "Filenames:"
    for b in record.attributes():
        if b.type() != ATTR_TYPE.FILENAME_INFORMATION:
            continue
        try:
            attr = FilenameAttribute(b.value(), 0, record)
            a = attr.filename_type()
            print "  Type: %s" % (["POSIX", "WIN32", "DOS 8.3", "WIN32 + DOS 8.3"][a])
            print "    name: %s" % (str(attr.filename()))
            print "    attributes: " + \
                ", ".join(get_flags(attr.flags()))
            print "    logical size:  %d bytes" % (attr.logical_size())
            print "    physical size: %d bytes" % (attr.physical_size())

            crtime = attr.created_time().isoformat("T") + "Z"
            mtime = attr.modified_time().isoformat("T") + "Z"
            chtime = attr.changed_time().isoformat("T") + "Z"
            atime = attr.accessed_time().isoformat("T") + "Z"

            print "    modified: %s" % (mtime)
            print "    accessed: %s" % (atime)
            print "    changed: %s" % (chtime)
            print "    birthed: %s" % (crtime)
            print "    parent ref: %d" % (MREF(attr.mft_parent_reference()))
            print "    parent seq: %d" % (MSEQNO(attr.mft_parent_reference()))
        except ZeroDivisionError:
            continue

    print "Attributes:"
    for b in record.attributes():
        print "  %s" % (Attribute.TYPES[b.type()])
        print "    attribute name: %s" % (b.name() or "<none>")
        print "    attribute flags: " + \
            ", ".join(get_flags(attr.flags()))
        if b.non_resident() > 0:
            print "    resident: no"
            print "    data size: %d" % (b.data_size())
            print "    allocated size: %d" % (b.allocated_size())

            if b.allocated_size() > 0:
                print "    runlist:"
                for (offset, length) in b.runlist().runs():
                    print "      Cluster %s, length %s" % \
                        (hex(offset), hex(length))
                    print "        %s (%s) bytes for %s (%s) bytes" % \
                        (offset * options.clustersize,
                         hex(offset * options.clustersize),
                         length * options.clustersize,
                         hex(length * options.clustersize))
        else:
            print "    resident: yes"
            print "    size: %d bytes" % (b.value_length())

    # INDX stuff
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
            print "    " + str(e.filename_information().logical_size()) + " bytes in size"
            print "    b " + e.filename_information().created_time().isoformat("T") + "Z"
            print "    m " + e.filename_information().modified_time().isoformat("T") + "Z"
            print "    c " + e.filename_information().changed_time().isoformat("T") + "Z"
            print "    a " + e.filename_information().accessed_time().isoformat("T") + "Z"

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
                         (offset * options.clustersize) + options.offset,
                         hex((offset * options.clustersize) + options.offset),
                         length * options.clustersize,
                         hex(length * options.clustersize))
                    ooff = offset * options.clustersize + options.offset
                    llen = length * options.clustersize
                    extractbuf += f.read(ooff, llen)
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


def main():
    parser = argparse.ArgumentParser(description='Parse NTFS '
                                     'filesystem structures.')
    parser.add_argument('-t', action="store", metavar="type",
                        nargs=1, dest="filetype",
                        choices=["image", "MFT", "INDX", "auto"],
                        default="auto",
                        help="The type of data provided.")
    parser.add_argument('-c', action="store", metavar="size",
                        nargs=1, type=int, dest="clustersize",
                        help="Use this cluster size in bytes "
                        "(default 4096 bytes)")
    parser.add_argument('-o', action="store", metavar="offset",
                        nargs=1, type=int, dest="offset",
                        help="Offset in bytes to volume in image "
                        "(default 32256 bytes)")
    parser.add_argument('-l', action="store_true", dest="indxlist",
                        help="List file entries in INDX records")
    parser.add_argument('-s', action="store_true", dest="slack",
                        help="List file entries in INDX slack space")
    parser.add_argument('-m', action="store_true", dest="mftlist",
                        help="List file entries for active MFT records")
    parser.add_argument('-d', action="store_true", dest="deleted",
                        help="List file entries for MFT records "
                        "marked as deleted")
    parser.add_argument('-i', action="store", metavar="path|inode",
                        nargs=1, dest="infomode",
                        help="Print information about a path's INDX records")
    parser.add_argument('-e', action="store", metavar="i30",
                        nargs=1, dest="extract",
                        help="Used with -i, extract INDX_ALLOCATION "
                        "attribute to a file")
    parser.add_argument('-f', action="store", metavar="regex",
                        nargs=1, dest="filter",
                        help="Only consider entries whose path "
                        "matches this regular expression")
    parser.add_argument('-p', action="store", metavar="prefix",
                        nargs=1, dest="prefix",
                        help="Prefix paths with `prefix` rather than \\.\\")
    parser.add_argument('--progress', action="store_true",
                        dest="progress",
                        help="Update a status indicator on STDERR "
                        "if STDOUT is redirected")
    parser.add_argument('-v', action="store_true", dest="verbose",
                        help="Print debugging information")
    parser.add_argument('filename', action="store",
                        help="Input INDX file path")

    results = parser.parse_args()

    global verbose
    verbose = results.verbose

    if results.filetype and results.filetype != "auto":
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
        info("Using explicit file system cluster size %s (%s) bytes" %
             (str(results.clustersize), hex(results.clustersize)))
    else:
        results.clustersize = 4096
        info("Assuming file system cluster size %s (%s) bytes" %
             (str(results.clustersize), hex(results.clustersize)))

    if results.offset:
        results.offset = results.offset[0]
        info("Using explicit volume offset %s (%s) bytes" %
             (str(results.offset), hex(results.offset)))
    else:
        results.offset = 32256
        info("Assuming volume offset %s (%s) bytes" %
             (str(results.offset), hex(results.offset)))

    if results.prefix:
        results.prefix = results.prefix[0]
        info("Using path prefix " + results.prefix)

    if results.indxlist:
        info("Asked to list entries in INDX records")
        if results.filetype == "mft":
            info("  Note, only resident INDX records can be processed "
                 "with an MFT input file")
            info("  If you find an interesting record, "
                 "use -i to identify the relevant INDX record clusters")
        elif results.filetype == "indx":
            info("  Note, only records in this INDX record will be listed")
        elif results.filetype == "image":
            pass
        else:
            pass

    if results.slack:
        info("Asked to list slack entries in INDX records")
        info("  Note, this uses a scanning heuristic to identify records. "
             "These records may be corrupt or out-of-date.")

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
            error("Information mode (-i) cannot be run "
                  "with file entry list modes (-l/-s/-m/-d)")

        if results.extract:
            results.extract = results.extract[0]
            info("Asked to extract INDX_ALLOCATION attribute "
                 "for the path " + results.infomode)

    if results.extract and not results.infomode:
        warning("Extract (-e) doesn't make sense "
                "without information mode (-i)")

    if results.extract and not results.filetype == "image":
        error("Cannot extract non-resident attributes "
              "from anything but an image")

    if not (results.indxlist or
            results.slack or
            results.mftlist or
            results.deleted or
            results.infomode):
        error("You must choose a mode (-i/-l/-s/-m/-d)")

    if results.filter:
        results.filter = results.filter[0]
        info("Asked to only list file entry information "
             "for paths matching the regular expression: " + results.filter)
        if results.infomode:
            warning("This filter has no meaning with information mode (-i)")

    if results.infomode:
        print_indx_info(results)
    elif results.indxlist or \
         results.slack or \
         results.mftlist or \
         results.deleted:
        print_bodyfile(results)


if __name__ == '__main__':
    main()

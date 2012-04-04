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
#   Version v.1.1.8
from MFT import *

verbose = False
import argparse

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
                                              size, accessed, modified, changed, 
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
                         (offset * options.clustersize) + options.offset, hex((offset * options.clustersize) + options.offset),
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
    
def main():
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
    


if __name__ == '__main__':
    main()

#!/usr/bin/env python

from __future__ import with_statement

import os
import sys
import stat
import errno
import inspect
import calendar

from fuse import FUSE, FuseOSError, Operations, fuse_get_context

from Progress import ProgressBarProgress
from BinaryParser import Mmap
from MFT import MFTTree
from MFT import Cache
from MFT import MFTEnumerator
from get_file_info import format_record


PERMISSION_ALL_READ = int("444", 8)


def unixtimestamp(ts):
    """
    unixtimestamp converts a datetime.datetime to a UNIX timestamp.
    @type ts: datetime.datetime
    @rtype: int
    """
    return calendar.timegm(ts.utctimetuple())


def log(func):
    """
    log is a decorator that logs the a function call with its
      parameters and return value.
    """
    def inner(*args, **kwargs):
        func_name = inspect.stack()[3][3]
        if func_name == "_wrapper":
            func_name = inspect.stack()[2][3]
        (uid, gid, pid) = fuse_get_context()
        pre = "(%s: UID=%d GID=%d PID=%d ARGS=(%s) KWARGS=(%s))" % (
            func_name, uid, gid, pid,
            ", ".join(map(str, list(args)[1:])), str(**kwargs))
        try:
            ret = func(*args, **kwargs)
            post = "  +--> %s" % (str(ret))
            sys.stderr.write("%s\n%s\n" % (pre, post))
            return ret
        except Exception as e:
            post = "  +--> %s" % (str(e))
            sys.stderr.write("%s\n%s" % (pre, post))
            raise e
    return inner


class FH(object):
    """
    FH is a class used to represent a file handle.
    Subclass it and override the get_data and get_size methods
      for specific behavior.
    """
    def __init__(self, fh, record):
        super(FH, self).__init__()
        self._fh = fh
        self._record = record

    def get_data(self):
        """
        Return a bytestring containing the data of the opened file.
        @rtype: str
        """
        raise RuntimeError("FH.get_data not implemented")

    def get_size(self):
        """
        @rtype: int
        """
        raise RuntimeError("FH.get_size not implemented")

    def get_fh(self):
        return self._fh


class RegularFH(FH):
    """
    RegularFH is a class used to represent an open file.
    """
    def __init__(self, fh, record):
        super(RegularFH, self).__init__(fh, record)

    def get_data(self):
        data_attribute = self._record.data_attribute()
        if data_attribute is not None and \
           data_attribute.non_resident() == 0:
                return data_attribute.value()
        return ""

    def get_size(self):
        data_attribute = self._record.data_attribute()
        if data_attribute is not None:
            if data_attribute.non_resident() == 0:
                return len(self.get_data())
            else:
                return data_attribute.data_size()
        else:
            return self._record.standard_information.logical_size()


def get_meta_for_file(record, path, buf):
    """
    Given an MFT record, print out metadata about the relevant file.
    @type record: MFT.MFTRecord
    @type path: str
    @type buf: str
    @rtype: str
    """
    return format_record(record, path, buf)


class MetaFH(FH):
    """
    A class used to represent a virtual file containing metadata
      for a regular file.
    """
    def __init__(self, fh, record, path, record_buf):
        super(MetaFH, self).__init__(fh, record)
        self._path = path
        self._record_buf = record_buf

    def get_data(self):
        return get_meta_for_file(self._record, self._path, self._record_buf)

    def get_size(self):
        return len(self.get_data())


def is_special_file(path):
    """
    is_special_file returns true if the file path is a special/virtual file.
    @type path: str
    @rtype: boolean
    """
    return "::" in path.rpartition("/")[2]


def explode_special_file(path):
    """
    explode_special_file breaks apart the path of a special/virtual file into
      its base path and special file identifier.
    @type path: str
    @rtype: (str, str)
    """
    (base, _, special) = path.rpartition("::")
    return base, special


class MFTFuseOperations(Operations):
    """
    MFTFuseOperations is a FUSE driver for NTFS MFT files.
    """
    def __init__(self, root, mfttree, buf):
        self._root = root
        self._tree = mfttree
        self._buf = buf
        self._opened_files = {}  # dict(int --> FH subclass)

        record_cache = Cache(1024)
        path_cache = Cache(1024)

        self._enumerator = MFTEnumerator(buf,
                             record_cache=record_cache,
                             path_cache=path_cache)

    # Helpers
    # =======
    def _get_node(self, path):
        """
        _get_node returns the MFTTreeNode associated with a path.
        @type path: str
        @rtype: MFT.MFTTreeNode
        @raises: FuseOSError(errno.ENOENT)
        """
        if path.startswith("/"):
            path = path[1:]

        current_node = self._tree.get_root()
        for component in path.split("/"):
            if component == "":
                continue
            try:
                current_node = current_node.get_child_node(component)
            except KeyError:
                raise FuseOSError(errno.ENOENT)

        return current_node

    def _get_record(self, path):
        """
        _get_record returns the MFTRecord associated with a path.
        @type path: str
        @rtype: MFT.MFTRecord
        """
        return self._enumerator.get_record(self._get_node(path).get_record_number())

    # Filesystem methods
    # ==================
    @log
    def getattr(self, path, fh=None):
        (uid, gid, pid) = fuse_get_context()

        working_path = path

        if is_special_file(path):
            (working_path, special) = explode_special_file(working_path)

        record = self._get_record(working_path)
        if record.is_directory():
            mode = (stat.S_IFDIR | PERMISSION_ALL_READ)
            nlink = 2
        else:
            mode = (stat.S_IFREG | PERMISSION_ALL_READ)
            nlink = 1

        # TODO(wb): fix the duplication of this code with the FH classes
        if is_special_file(path):
            size = 0
            (working_path, special) = explode_special_file(path)
            if special == "meta":
                node = self._get_node(working_path)
                record_buf = self._enumerator.get_record_buf(node.get_record_number())
                size = len(get_meta_for_file(record, working_path, record_buf))
        else:
            data_attribute = record.data_attribute()
            if data_attribute is not None:
                if data_attribute.non_resident() == 0:
                    size = len(data_attribute.value())
                else:
                    size = data_attribute.data_size()
            else:
                size = record.filename_information().logical_size()

        return {
            "st_atime": unixtimestamp(record.standard_information().accessed_time()),
            "st_ctime": unixtimestamp(record.standard_information().changed_time()),
            #"st_crtime": unixtimestamp(record.standard_information().created_time()),
            "st_mtime": unixtimestamp(record.standard_information().modified_time()),
            "st_size": size,
            "st_uid": uid,
            "st_gid": gid,
            "st_mode": mode,
            "st_nlink": nlink,
        }

    @log
    def readdir(self, path, fh):
        dirents = ['.', '..']
        record = self._get_node(path)
        dirents.extend(map(lambda r: r.get_filename(), record.get_children_nodes()))
        for r in dirents:
            yield r

    @log
    def readlink(self, path):
        return path

    @log
    def statfs(self, path):
        return dict((key, 0) for key in ('f_bavail', 'f_bfree',
                                         'f_blocks', 'f_bsize', 'f_favail',
                                         'f_ffree', 'f_files', 'f_flag',
                                         'f_frsize', 'f_namemax'))

    @log
    def chmod(self, path, mode):
        return errno.EROFS

    @log
    def chown(self, path, uid, gid):
        return errno.EROFS

    @log
    def mknod(self, path, mode, dev):
        return errno.EROFS

    @log
    def rmdir(self, path):
        return errno.EROFS

    @log
    def mkdir(self, path, mode):
        return errno.EROFS

    @log
    def unlink(self, path):
        return errno.EROFS

    @log
    def symlink(self, target, name):
        return errno.EROFS

    @log
    def rename(self, old, new):
        return errno.EROFS

    @log
    def link(self, target, name):
        return errno.EROFS

    @log
    def utimens(self, path, times=None):
        return errno.EROFS

    # File methods
    # ============

    def _get_available_fh(self):
        """
        _get_available_fh returns an unused fh
        The caller must be careful to handle race conditions.
        @rtype: int
        """
        for i in xrange(65534):
            if i not in self._opened_files:
                return i

    @log
    def open(self, path, flags):
        if flags & os.O_WRONLY > 0:
            return errno.EROFS
        if flags & os.O_RDWR > 0:
            return errno.EROFS

        # TODO(wb): race here on fh used/unused
        fh = self._get_available_fh()
        if is_special_file(path):
            (path, special) = explode_special_file(path)
            if special == "meta":
                record = self._get_record(path)
                node = self._get_node(path)
                record_buf = self._enumerator.get_record_buf(node.get_record_number())
                self._opened_files[fh] = MetaFH(fh, record, path, record_buf)
            else:
                raise FuseOSError(errno.ENOENT)
        else:
            self._opened_files[fh] = RegularFH(fh, self._get_record(path))

        return fh

    @log
    def read(self, path, length, offset, fh):
        txt = self._opened_files[fh].get_data().encode("utf-8")
        return txt[offset:offset+length]

    @log
    def flush(self, path, fh):
        return ""

    @log
    def release(self, path, fh):
        del self._opened_files[fh]

    @log
    def create(self, path, mode, fi=None):
        return errno.EROFS

    @log
    def write(self, path, buf, offset, fh):
        return errno.EROFS

    @log
    def truncate(self, path, length, fh=None):
        return errno.EROFS

    @log
    def fsync(self, path, fdatasync, fh):
        return errno.EPERM


def main(mft_filename, mountpoint):
    with Mmap(mft_filename) as buf:
        tree = MFTTree(buf)
        tree.build(progress_class=ProgressBarProgress)
        handler = MFTFuseOperations(mountpoint, tree, buf)
        FUSE(handler, mountpoint, foreground=True)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

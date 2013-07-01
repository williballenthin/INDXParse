#!/usr/bin/python

#    This file is part of INDXParse.
#
#   Copyright 2012 Willi Ballenthin <william.ballenthin@mandiant.com>
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
#   Version v.2.0.0
import sys
import re
import array

import wx
import wx.lib.scrolledpanel as scrolled
import wx.lib.newevent
from wx.lib.evtmgr import eventManager

from MFT import NTFSFile
from MFT import MFTRecord
from MFT import IndexRootHeader
from MFT import ATTR_TYPE
from MFT import FilenameAttribute
from MFT import InvalidMFTRecordNumber


verbose = False

# RecordUpdatedEvent
# @param record The updated record.
RecordUpdatedEvent, EVT_RECORD_UPDATED_EVENT = wx.lib.newevent.NewEvent()

# VolumeOffsetUpdatedEvent
# @param volume_offset The volume offset in bytes.
VolumeOffsetUpdatedEvent, EVT_VOLUME_OFFSET_UPDATED_EVENT = wx.lib.newevent.NewEvent()

# ClusterSizeUpdatedEvent
# @param cluster_size The cluster size in bytes.
ClusterSizeUpdatedEvent, EVT_CLUSTER_SIZE_UPDATED_EVENT = wx.lib.newevent.NewEvent()


def nop(*args, **kwargs):
    pass


def _expand_into(dest, src):
    vbox = wx.BoxSizer(wx.VERTICAL)
    vbox.Add(src, 1, wx.EXPAND | wx.ALL)
    dest.SetSizer(vbox)


def _format_hex(data):
    """
    see http://code.activestate.com/recipes/142812/
    """
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.'
                      for x in range(256)])

    def dump(src, length=16):
        N = 0
        result = ''
        while src:
            s, src = src[:length], src[length:]
            hexa = ' '.join(["%02X" % ord(x) for x in s])
            s = s.translate(FILTER)
            result += "%04X   %-*s   %s\n" % (N, length * 3, hexa, s)
            N += length
        return result
    return dump(data)


class Node():
    """
    A node in the file system directory structure.
    """
    def __init__(self, number, name, parent, is_directory):
        """
        @type number: int
        @param number: the inode number of this node
        @type name: str
        @param name: the filename of this node
        @type parent: Node
        @param parent: the parent node of this node, or None if there is no parent
        @type is_directory: bool
        @param is_directory: true if the node is a directory, false otherwise.
        """
        self._number = number
        self._name = name
        self._parent = parent
        self.children = []  # public
        self.is_directory = is_directory

    def add_child(self, child):
        self.children.append(child)

    def get_name(self):
        return self._name


class AppModel(wx.EvtHandler):
    """
    @emit EVT_RECORD_UPDATED_EVENT
    @emit EVT_VOLUME_OFFSET_UPDATED_EVENT
    @emit EVT_CLUSTER_SIZE_UPDATED_EVENT
    """
    def __init__(self, filename, record):
        super(AppModel, self).__init__()
        self._filename = filename
        self._nodes = {}
        self._orphans = []
        self._record = record
        self._volume_offset = 32256
        self._cluster_size = 4096

    def GetId(self):
        """
        At the moment, this must be a singleton...
        """
        return 1

    def set_volume_offset(self, volume_offset):
        self._volume_offset = volume_offset
        wx.PostEvent(self, VolumeOffsetUpdatedEvent(volume_offset=volume_offset))

    def set_cluster_size(self, cluster_size):
        self._cluster_size = cluster_size
        wx.PostEvent(self, ClusterSizeUpdatedEvent(cluster_size=cluster_size))

    def volume_offset(self):
        return self._volume_offset

    def cluster_size(self):
        return self._cluster_size

    def set_record(self, record):
        self._record = record
        wx.PostEvent(self, RecordUpdatedEvent(record=record))

    def record(self):
        return self._record

    def get_root(self):
        return self.get_node(5)

    def get_node(self, rec_num):
        if len(self._nodes) == 0:
            self.fetch()
        return self._nodes[rec_num]

    def fetch(self, progress_fn=nop):
        """
        @param progress_fn - A function(count, total) called periodically
        """
        if len(self._nodes) > 0:
            return

        with open(self._filename, "rb") as f:
            f.seek(0, 2)  # end
            total_count = f.tell() / 1024
            f.seek(0)

        f = NTFSFile({
            "filename": self._filename,
            "filetype": "mft",
            "offset": 0,
            "clustersize": 4096,
            "prefix": "C:",
            "progress": False,
        })

        class RecordConflict(Exception):
            def __init__(self, count):
                self.value = count

        def add_node(mftfile, record):
            """
            Add the given record to the internal list of nodes,
              adding the parent nodes as appropriate.

            This is what usually happens:
              add a node, recursively add its parent
              if there parent already exists, exit
              if the parent is new, add and keep recursing
              recurse until we hit the root node

            There are some edge cases we need to catch:
              - cycles, where a node's parent is the same node
              - orphans, where a node's parent is invalid

            Depends on the closure of `nodes` and `orphans`
            @raises RecordConflict if the record already exists in nodes
            """
            rec_num = record.inode
            if record.magic() != 0x454c4946:
                if record.magic() == int("BAAD", 0x16):
                    node = Node(rec_num, "BAAD",
                        None, record.is_directory())
                    self._orphans.append(node)
                    self._nodes[rec_num] = node
                else:
                    # ignore this guy
                    return

            # node already exists by rec_num
            if rec_num in self._nodes:
                raise RecordConflict(rec_num)

            # no filename info --> orphan with name "???"
            fn = record.filename_information()
            if not fn:
                node = Node(rec_num, "???", None, record.is_directory())
                self._orphans.append(node)
                self._nodes[rec_num] = node
                return

            # detect one level cycle
            parent_record_num = fn.mft_parent_reference() & 0xFFFFFFFFFFFF
            if parent_record_num == rec_num:
                node = Node(rec_num, fn.filename(),
                            None, record.is_directory())
                self._orphans.append(node)
                self._nodes[rec_num] = node
                return

            if record.inode == 0x5:
                # this is madeness to use record.inode and rec_num
                # but its possible that the root node points to itself
                # and creates a cycle
                node = Node(record.inode, fn.filename(),
                            None, record.is_directory())
                self._nodes[record.inode] = node
                return

            if parent_record_num not in self._nodes:
                # no parent --> orphan with correct filename
                parent_buf = mftfile.mft_get_record_buf(parent_record_num)
                if parent_buf == array.array("B", ""):
                    node = Node(rec_num, fn.filename(),
                                None, record.is_directory())
                    self._orphans.append(node)
                    self._nodes[rec_num] = node
                    return

                # parent sequence num incorrect -->
                #  orphan with correct filename
                parent = MFTRecord(parent_buf, 0, False, inode=parent_record_num)
                if parent.sequence_number() != fn.mft_parent_reference() >> 48:
                    node = Node(rec_num, fn.filename(),
                                None, record.is_directory())
                    self._orphans.append(node)
                    self._nodes[rec_num] = node
                    return

                add_node(mftfile, parent)

            parent_node = self._nodes[parent_record_num]
            node = Node(rec_num, fn.filename(),
                        parent_node, record.is_directory())
            parent_node.add_child(node)
            self._nodes[rec_num] = node
            return

        count = 0
        for record in f.record_generator(start_at=count):
            count += 1

            if count % 100 == 0:
                progress_fn(count, total_count)

            try:
                add_node(f, record)
            except RecordConflict:
                # this is expected.
                # this record must be a directory, and a descendant has already
                # been processed.
                pass


class MFTTreeCtrl(wx.TreeCtrl):
    """
    A nice treeview of the file system.
    @param model (keyword, required) An AppModel instance.
    """
    def __init__(self, *args, **kwargs):
        self._model = kwargs.get("model", None)
        del kwargs["model"]
        super(MFTTreeCtrl, self).__init__(*args, **kwargs)
        self.Bind(wx.EVT_TREE_ITEM_EXPANDING, self.OnExpandKey)

        self.il = wx.ImageList(16, 16)
        self._folder_icon = self.il.Add(wx.ArtProvider.GetBitmap(wx.ART_FOLDER,
                                                                 wx.ART_OTHER,
                                                                 (16, 16)))

        ico = self.il.Add(wx.ArtProvider.GetBitmap(wx.ART_NORMAL_FILE,
                                                   wx.ART_OTHER,
                                                   (16, 16)))
        self._file_icon = ico

        self.SetImageList(self.il)

        dialog = wx.ProgressDialog('Loading MFT', '0.00% Complete',
                                   maximum=100.0,
                                   style=wx.PD_AUTO_HIDE |
                                       wx.PD_APP_MODAL |
                                       wx.PD_CAN_ABORT |
                                       wx.PD_ELAPSED_TIME |
                                       wx.PD_ESTIMATED_TIME |
                                       wx.PD_REMAINING_TIME)

        def progress_update(count, total):
            update_str = "%d / %d\n%0.2f%% Complete\n" % \
                         (count, total, 100 * count / float(total))
            (cont, skip) = dialog.Update(100 * count / float(total),
                                         update_str)
            if not cont:
                sys.exit(0)
        self._model.fetch(progress_fn=progress_update)
        dialog.Update(100.0)

        root = self._model.get_root()
        root_item = self.AddRoot(root.get_name(), self._folder_icon)
        self.SetPyData(root_item, {
            "rec_num": root._number,
            "has_expanded": False,
        })
        if len(root.children) > 0:
            self.SetItemHasChildren(root_item)

    def _extend(self, item):
        if self.GetPyData(item)["has_expanded"]:
            return

        rec_num = self.GetPyData(item)["rec_num"]
        node = self._model.get_node(rec_num)
        for child_node in sorted([c for c in node.children if c.is_directory],
                                 key=lambda x: x.get_name()):
            child_item = self.AppendItem(item, child_node.get_name())
            self.SetItemImage(child_item, self._folder_icon)
            self.SetPyData(child_item, {
                "rec_num": child_node._number,
                "has_expanded": False,
            })
            if len(child_node.children) > 0:
                self.SetItemHasChildren(child_item)
        for child_node in sorted([c for c in node.children
                                  if not c.is_directory],
                                 key=lambda x: x.get_name()):
            child_item = self.AppendItem(item, child_node.get_name())
            self.SetItemImage(child_item, self._file_icon)
            self.SetPyData(child_item, {
                "rec_num": child_node._number,
                "has_expanded": False,
            })
        self.GetPyData(item)["has_expanded"] = True

    def OnExpandKey(self, event):
        item = event.GetItem()
        if not item.IsOk():
            item = self.GetSelection()
        if not self.GetPyData(item)["has_expanded"]:
            self._extend(item)


class LabelledLine(wx.Panel):
    """
    A simple panel that contains a key and value,
      or label and some text.
    @param label A string.
    @param value Something that can be str()'d.
    """
    def __init__(self, parent, label, value):
        super(LabelledLine, self).__init__(parent, -1)
        self._sizer = wx.BoxSizer(wx.HORIZONTAL)
        self._sizer.Add(wx.StaticText(self, -1, label), 1, wx.EXPAND)
        self._text = wx.TextCtrl(self, -1, style=wx.TE_LEFT | wx.TE_READONLY)
        self._sizer.Add(self._text, 1, wx.EXPAND)
        self.SetSizer(self._sizer)
        self.update(value)

    def update(self, value):
        self._text.SetValue(str(value))


class RunlistPanel(wx.Panel):
    """
    Display the details of one entry in a runlist,
      which is an (offset, length) tuple.
    Show both offsets in clusters (relative to the volume)
      and bytes (relative to the disk).
    Updates these values as changes are made to the
      disk geometry model.
    @param offset An integer, in clusters relative to the volume.
    @param length An integer, in clusters.
    @param model An AppModel intance.
    """
    def __init__(self, parent, offset, length, model):
        super(RunlistPanel, self).__init__(parent, -1)

        self._offset = offset
        self._length = length
        self._model = model
        self._sizer = wx.BoxSizer(wx.HORIZONTAL)

        sb = wx.StaticBox(self, -1, "Cluster Run")
        sbs = wx.StaticBoxSizer(sb, wx.VERTICAL)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        hbox3 = wx.BoxSizer(wx.HORIZONTAL)
        hbox4 = wx.BoxSizer(wx.HORIZONTAL)
        hbox5 = wx.BoxSizer(wx.HORIZONTAL)

        hbox1.Add(wx.StaticText(self, label="Offset (clusters)"), 1, wx.EXPAND)
        self._base_offset_text = wx.TextCtrl(self, -1,
                                             "", style=wx.TE_READONLY)
        hbox1.Add(self._base_offset_text, 1, wx.EXPAND)

        hbox2.Add(wx.StaticText(self, label="Length (clusters)"), 1, wx.EXPAND)
        self._base_length_text = wx.TextCtrl(self, -1, "",
                                             style=wx.TE_READONLY)
        hbox2.Add(self._base_length_text, 1, wx.EXPAND)

        hbox3.Add(wx.StaticText(self, label="Offset (bytes)"), 1, wx.EXPAND)
        self._cluster_offset_text = wx.TextCtrl(self, -1, "",
                                                style=wx.TE_READONLY)
        hbox3.Add(self._cluster_offset_text, 1, wx.EXPAND)

        hbox4.Add(wx.StaticText(self, label="Length (bytes)"), 1, wx.EXPAND)
        self._cluster_length_text = wx.TextCtrl(self, -1, "",
                                                style=wx.TE_READONLY)
        hbox4.Add(self._cluster_length_text, 1, wx.EXPAND)

        hbox5.Add(wx.StaticLine(self, -1, size=(200, 4),
                                style=wx.LI_HORIZONTAL), 1, wx.EXPAND)
        sbs.Add(hbox1, 1, wx.EXPAND)
        sbs.Add(hbox2, 1, wx.EXPAND)
        sbs.Add(hbox3, 1, wx.EXPAND)
        sbs.Add(hbox4, 1, wx.EXPAND)
        sbs.Add(hbox5, 1, wx.EXPAND)

        self._sizer.Add(sbs, -1, wx.EXPAND)
        self.SetSizer(self._sizer)
        self.Layout()

        self.update(None)
        eventManager.Register(self.update,
                              EVT_VOLUME_OFFSET_UPDATED_EVENT, self._model)
        eventManager.Register(self.update,
                              EVT_CLUSTER_SIZE_UPDATED_EVENT, self._model)

    def __del__(self, *args, **kwargs):
        eventManager.DeregisterListener(self.update)
        eventManager.DegisterDeadTopics()
        super(RunlistPanel, self).__del__(*args, **kwargs)

    def update(self, event):
        self._base_offset_text.SetValue(str(self._offset))
        self._base_length_text.SetValue(str(self._length))
        coff = str(self._model.volume_offset() + self._offset * self._model.cluster_size())
        clen = str(self._length * self._model.cluster_size())
        self._cluster_offset_text.SetValue(coff)
        self._cluster_length_text.SetValue(clen)


class DiskGeometryWarningPanel(wx.Panel):
    """
    Reminds the user that byte offsets are dependent
      upon the disk geometry, such as the volume offset
      and cluster size.
    Also, gives the user a place to update these values.
    """
    def __init__(self, parent, model):
        super(DiskGeometryWarningPanel, self).__init__(parent, -1)
        self._model = model
        self._sizer = wx.BoxSizer(wx.HORIZONTAL)

        sb = wx.StaticBox(self, -1, "NOTE: Check Disk Geometry")
        sbs = wx.StaticBoxSizer(sb, wx.VERTICAL)
        sbs.Add(wx.StaticText(self, label="""
          These byte offsets assume the following disk geometry.
          Please double check the geometry and update it here.
"""), 0, wx.EXPAND)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        self._volume_offset_label_ok = "Volume Offset (bytes)"
        self._volume_offset_label_fail = "Volume Offset (bytes) INVALID"
        self._volume_offset_label = wx.TextCtrl(self, -1,
                                                self._volume_offset_label_ok,
                                                style=wx.TE_READONLY)

        hbox1.Add(self._volume_offset_label, 1, wx.EXPAND)
        self._volume_offset_text = wx.TextCtrl(self, -1, str(self._model.volume_offset()))
        self._volume_offset_text.Bind(wx.EVT_TEXT, self._volume_offset_changed)
        hbox1.Add(self._volume_offset_text, 0, wx.EXPAND)

        self._cluster_size_label_ok = "Cluster Size (bytes)"
        self._cluster_size_label_fail = "Cluster Size (bytes) INVALID"
        self._cluster_size_label = wx.TextCtrl(self, -1,
                                                 self._cluster_size_label_ok,
                                                 style=wx.TE_READONLY)
        hbox1.Add(self._cluster_size_label, 1, wx.EXPAND)
        self._cluster_size_text = wx.TextCtrl(self, -1,
                                              str(self._model.cluster_size()))
        self._cluster_size_text.Bind(wx.EVT_TEXT, self._cluster_size_changed)
        hbox1.Add(self._cluster_size_text, 0, wx.EXPAND)

        sbs.Add(hbox1, 0, wx.EXPAND)
        sbs.Add(wx.StaticLine(self, -1, size=(200, 4),
                              style=wx.LI_HORIZONTAL), 1, wx.EXPAND)

        self._sizer.Add(sbs, -1, wx.EXPAND)
        self.SetSizer(self._sizer)
        self.Layout()

        eventManager.Register(self._updated_volume_offset,
                              EVT_VOLUME_OFFSET_UPDATED_EVENT,
                              self._model)
        eventManager.Register(self._updated_cluster_size,
                              EVT_CLUSTER_SIZE_UPDATED_EVENT,
                              self._model)

    def __del__(self, *args, **kwargs):
        self._volume_offset_text.Unbind(wx.EVT_TEXT)
        self._cluster_size_text.Unbind(wx.EVT_TEXT)
        eventManager.DeregisterListener(self._updated_volume_offset)
        eventManager.DeregisterListener(self._updated_cluster_size)
        eventManager.DeregisterDeadTopics()
        super(DiskGeometryWarningPanel, self).__del__(*args, **kwargs)

    def _volume_offset_changed(self, event):
        """
        Called when the user inputs text in this panel to
        change the volume offset.
        """
        new_value = self._volume_offset_text.GetValue()
        try:
            new_value = int(new_value)
            self._model.set_volume_offset(new_value)
            self._volume_offset_label.SetValue(self._volume_offset_label_ok)
        except ValueError:
            self._volume_offset_label.SetValue(self._volume_offset_label_fail)

    def _cluster_size_changed(self, event):
        """
        Called when the user inputs text in this panel to
        change the cluster size.
        """
        new_value = self._cluster_size_text.GetValue()
        try:
            new_value = int(new_value)
            self._model.set_cluster_size(new_value)
            self._cluster_size_label.SetValue(self._cluster_size_label_ok)
        except ValueError:
            self._cluster_size_label.SetValue(self._cluster_size_label_fail)

    def _updated_volume_offset(self, event):
        """
        Called when the application model is changed that
        results in an updated volume offset.
        """

        # For some reason, references hang around and receive
        #   events, although they're invalid. So we skip them.
        #   And probably leak memory.
        if not self:
            return

        if not self._volume_offset_text.IsModified():
            voff = str(self._model.volume_offset())
            self._volume_offset_text.ChangeValue(voff)

    def _updated_cluster_size(self, event):
        """
        Called when the application model is changed that
        results in an updated cluster size.
        """

        # For some reason, references hang around and receive
        #   events, although they're invalid. So we skip them.
        #   And probably leak memory.
        if not self:
            return

        if not self._cluster_size_text.IsModified():
            csize = str(self._model.cluster_size())
            self._cluster_size_text.ChangeValue(csize)


class RecordPane(scrolled.ScrolledPanel):
    """
    Displays some information about an MFT record.
    This is a superclass to things that might show
      interesting information.
    @param model (keyword) A AppModel instance.
    """
    def __init__(self, *args, **kwargs):
        self._model = kwargs.get("model", None)
        try:
            del kwargs["model"]
        except KeyError:
            pass
        super(RecordPane, self).__init__(*args, **kwargs)
        self._sizer = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(self._sizer)

        # this is only for readability, and is
        # specific to the wx.VERTICAL box sizer
        # used here
        self.EXPAND_VERTICALLY = 1
        self.NOT_EXPAND_VERTICALLY = 0

        self.SetAutoLayout(1)
        self.SetupScrolling()

        eventManager.Register(self.update,
                              EVT_RECORD_UPDATED_EVENT,
                              self._model)

    def __del__(self, *args, **kwargs):
        eventManager.DeregisterListener(self.update)
        eventManager.DeregisterDeadTopics()
        super(RecordPane, self).__del__(*args, **kwargs)

    def update(self, event):
        print "Warning: Unbound Record Pane update"

ascii_byte = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~"


def ascii_strings(buf, n=4):
    reg = "([%s]{%d,})" % (ascii_byte, n)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        yield match.group().decode("ascii")


def unicode_strings(buf, n=4):
    reg = b"((?:[%s]\x00){4,})" % (ascii_byte)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        try:
            yield match.group().decode("utf-16")
        except UnicodeDecodeError:
            print "unicode find error: " + str(match.group())
            pass


def strings(buf):
    for string in ascii_strings(buf):
        yield string
    for string in unicode_strings(buf):
        yield string


class DataPane(wx.Panel):
    def __init__(self, *args, **kwargs):
        super(DataPane, self).__init__(*args, **kwargs)
        self._data = ""

        vsplitter = wx.SplitterWindow(self, -1)
        panel_left = wx.Panel(vsplitter, -1)
        self._text = wx.TextCtrl(panel_left, -1, style=wx.TE_MULTILINE)
        self._text.SetFont(wx.Font(8, wx.SWISS, wx.NORMAL,
                                   wx.NORMAL, False, u'Courier'))
        _expand_into(panel_left, self._text)

        panel_right = wx.Panel(vsplitter, -1)
        self._strings = wx.TextCtrl(panel_right, -1, style=wx.TE_MULTILINE)
        self._strings.SetFont(wx.Font(8, wx.SWISS, wx.NORMAL,
                                      wx.NORMAL, False, u'Courier'))
        _expand_into(panel_right, self._strings)

        vsplitter.SplitVertically(panel_left, panel_right, sashPosition=600)
        vsplitter.SetSashPosition(600, redraw=True)
        vsplitter.SetMinimumPaneSize(500)
        _expand_into(self, vsplitter)
        self.Centre()

    def update(self, data):
        self._data = data
        hhex = unicode(_format_hex(data))
        self._text.SetValue(hhex)

        strings_text = ""
        strings_text += "ASCII\n"
        strings_text += "----------------\n"
        for string in ascii_strings(data):
            strings_text += "%s\n" % (string)
        strings_text += "\n\nUTF-16\n"
        strings_text += "----------------\n"
        for string in unicode_strings(data):
            strings_text += "%s\n" % (string)
        self._strings.SetValue(strings_text)


class RecordHexPane(RecordPane):
    """
    Displays a hex dump of the entire MFT record.
    """
    def __init__(self, *args, **kwargs):
        super(RecordHexPane, self).__init__(*args, **kwargs)
        self._data_pane = DataPane(self, -1)
        _expand_into(self, self._data_pane)

    def update(self, event):
        data = self._model.record()._buf.tostring()
        self._data_pane.update(data)


class RecordMetadataPane(RecordPane):
    """
    Display metadata from the MFT record header, $SI, and $FN attributes.
    Warning, this has two pretty long methods...
    """
    def __init__(self, *args, **kwargs):
        super(RecordMetadataPane, self).__init__(*args, **kwargs)

        # note, the parent must be `self`
        record_box = wx.StaticBox(self, -1, "MFT Record")
        record_box_sizer = wx.StaticBoxSizer(record_box, wx.VERTICAL)
        # note, the parent must be `self`, not the `record_box`
        self._record_number = LabelledLine(self, "MFT Record Number", "")
        record_box_sizer.Add(self._record_number,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

        self._record_attributes_line = LabelledLine(self, "Attributes", "<none>")
        record_box_sizer.Add(self._record_attributes_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

        self._record_size_line = LabelledLine(self, "Size (bytes)", "")
        record_box_sizer.Add(self._record_size_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

        self._seq_line = LabelledLine(self, "Sequence Number", "")
        record_box_sizer.Add(self._seq_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

        # note, must add the sizer, not the `record_box`
        self._sizer.Add(record_box_sizer, self.NOT_EXPAND_VERTICALLY,
                        wx.EXPAND)

        self._si_box = wx.StaticBox(self, -1, "Standard Information Attribute")
        si_box_sizer = wx.StaticBoxSizer(self._si_box, wx.VERTICAL)

        self._si_attributes_line = LabelledLine(self, "Attributes", "<none>")
        si_box_sizer.Add(self._si_attributes_line, self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

        self._si_created_line = LabelledLine(self, "Created", "")
        si_box_sizer.Add(self._si_created_line,
                         self.NOT_EXPAND_VERTICALLY,
                         wx.EXPAND)

        self._si_modified_line = LabelledLine(self, "Modified", "")
        si_box_sizer.Add(self._si_modified_line,
                         self.NOT_EXPAND_VERTICALLY,
                         wx.EXPAND)

        self._si_changed_line = LabelledLine(self, "Changed", "")
        si_box_sizer.Add(self._si_changed_line,
                         self.NOT_EXPAND_VERTICALLY,
                         wx.EXPAND)

        self._si_accessed_line = LabelledLine(self, "Accessed", "")
        si_box_sizer.Add(self._si_accessed_line,
                         self.NOT_EXPAND_VERTICALLY,
                         wx.EXPAND)

        self._sizer.Add(si_box_sizer, self.NOT_EXPAND_VERTICALLY,
                        wx.EXPAND)

        class SimpleObject(object):
            def __init__(self, *args, **kwargs):
                super(SimpleObject, self).__init__(*args, **kwargs)

        self._fn = {}
        for a in [3, 1, 2, 0]:  # order so that most common at top
            self._fn[a] = SimpleObject()

            filename_type = ["POSIX", "WIN32", "DOS 8.3", "WIN32 + DOS 8.3"][a]
            self._fn[a].box = wx.StaticBox(self, -1,
                                      "Filename Information Attribute (%s)" %
                                      (filename_type))
            fn_box_sizer = wx.StaticBoxSizer(self._fn[a].box, wx.VERTICAL)
            self._fn[a].name_line = LabelledLine(self, "Filename", "")
            fn_box_sizer.Add(self._fn[a].name_line, self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

            self._fn[a].attributes_line = LabelledLine(self, "Attributes", "<none>")
            fn_box_sizer.Add(self._fn[a].attributes_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

            self._fn[a].alloc_size_line = LabelledLine(self,
                                                      "Allocated Size (bytes)",
                                                      "")
            fn_box_sizer.Add(self._fn[a].alloc_size_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

            self._fn[a].log_size_line = LabelledLine(self,
                                                     "Logical Size (bytes)",
                                                     "")
            fn_box_sizer.Add(self._fn[a].log_size_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

            self._fn[a].created_line = LabelledLine(self, "Created", "")
            fn_box_sizer.Add(self._fn[a].created_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

            self._fn[a].modified_line = LabelledLine(self, "Modified", "")
            fn_box_sizer.Add(self._fn[a].modified_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

            self._fn[a].changed_line = LabelledLine(self, "Changed", "")
            fn_box_sizer.Add(self._fn[a].changed_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

            self._fn[a].accessed_line = LabelledLine(self, "Accessed", "")
            fn_box_sizer.Add(self._fn[a].accessed_line,
                             self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

            self._sizer.Add(fn_box_sizer, self.NOT_EXPAND_VERTICALLY,
                            wx.EXPAND)

    def update(self, event):
        self._record_number.update(str(self._model.record().mft_record_number()))

        attributes = []
        if self._model.record().is_directory():
            attributes.append("directory")
        else:
            attributes.append("file")
        if self._model.record().is_active():
            attributes.append("active")
        else:
            attributes.append("deleted")
        if len(attributes) > 0:
            self._record_attributes_line.update(", ".join(attributes))
        else:
            self._record_attributes_line.update("<none>")

        size = 0
        if not self._model.record().is_directory():
            data_attr = self._model.record().data_attribute()
            if data_attr and data_attr.non_resident() > 0:
                size = data_attr.data_size()
            else:
                size = self._model.record().filename_information().logical_size()

        self._record_size_line.update(str(size))
        self._seq_line.update(str(self._model.record().sequence_number()))

        attributes = []
        if self._model.record().standard_information().attributes() & 0x01:
            attributes.append("readonly")
        if self._model.record().standard_information().attributes() & 0x02:
            attributes.append("hidden")
        if self._model.record().standard_information().attributes() & 0x04:
            attributes.append("system")
        if self._model.record().standard_information().attributes() & 0x08:
            attributes.append("unused-dos")
        if self._model.record().standard_information().attributes() & 0x10:
            attributes.append("directory-dos")
        if self._model.record().standard_information().attributes() & 0x20:
            attributes.append("archive")
        if self._model.record().standard_information().attributes() & 0x40:
            attributes.append("device")
        if self._model.record().standard_information().attributes() & 0x80:
            attributes.append("normal")
        if self._model.record().standard_information().attributes() & 0x100:
            attributes.append("temporary")
        if self._model.record().standard_information().attributes() & 0x200:
            attributes.append("sparse")
        if self._model.record().standard_information().attributes() & 0x400:
            attributes.append("reparse-point")
        if self._model.record().standard_information().attributes() & 0x800:
            attributes.append("compressed")
        if self._model.record().standard_information().attributes() & 0x1000:
            attributes.append("offline")
        if self._model.record().standard_information().attributes() & 0x2000:
            attributes.append("not-indexed")
        if self._model.record().standard_information().attributes() & 0x4000:
            attributes.append("encrypted")
        if self._model.record().standard_information().attributes() & 0x10000000:
            attributes.append("has-indx")
        if self._model.record().standard_information().attributes() & 0x20000000:
            attributes.append("has-view-index")
        if len(attributes) > 0:
            self._si_attributes_line.update(", ".join(attributes))
        else:
            self._si_attributes_line.update("<none>")

        crtime = self._model.record().standard_information().created_time().isoformat("T")
        self._si_created_line.update(crtime + "Z")

        mtime = self._model.record().standard_information().modified_time().isoformat("T")
        self._si_modified_line.update(mtime + "Z")

        chtime = self._model.record().standard_information().changed_time().isoformat("T")
        self._si_changed_line.update(chtime + "Z")

        atime = self._model.record().standard_information().accessed_time().isoformat("T")
        self._si_accessed_line.update(atime + "Z")

        for i in self._fn:
            self._fn[i].name_line.update("<not present>")
            self._fn[i].attributes_line.update("")
            self._fn[i].alloc_size_line.update("")
            self._fn[i].log_size_line.update("")
            self._fn[i].created_line.update("")
            self._fn[i].modified_line.update("")
            self._fn[i].changed_line.update("")
            self._fn[i].accessed_line.update("")

        for b in self._model.record().attributes():
            if b.type() != ATTR_TYPE.FILENAME_INFORMATION:
                continue
            try:
                attr = FilenameAttribute(b.value(), 0, self)
                a = attr.filename_type()

                self._fn[a].name_line.update(str(attr.filename()))

                attributes = []
                if attr.flags() & 0x01:
                    attributes.append("readonly")
                if attr.flags() & 0x02:
                    attributes.append("hidden")
                if attr.flags() & 0x04:
                    attributes.append("system")
                if attr.flags() & 0x08:
                    attributes.append("unused-dos")
                if attr.flags() & 0x10:
                    attributes.append("directory-dos")
                if attr.flags() & 0x20:
                    attributes.append("archive")
                if attr.flags() & 0x40:
                    attributes.append("device")
                if attr.flags() & 0x80:
                    attributes.append("normal")
                if attr.flags() & 0x100:
                    attributes.append("temporary")
                if attr.flags() & 0x200:
                    attributes.append("sparse")
                if attr.flags() & 0x400:
                    attributes.append("reparse-point")
                if attr.flags() & 0x800:
                    attributes.append("compressed")
                if attr.flags() & 0x1000:
                    attributes.append("offline")
                if attr.flags() & 0x2000:
                    attributes.append("not-indexed")
                if attr.flags() & 0x4000:
                    attributes.append("encrypted")
                if attr.flags() & 0x10000000:
                    attributes.append("has-indx")
                if attr.flags() & 0x20000000:
                    attributes.append("has-view-index")
                if len(attributes) > 0:
                    self._fn[a].attributes_line.update(", ".join(attributes))
                else:
                    self._fn[a].attributes_line.update("<none>")

                self._fn[a].alloc_size_line.update(str(attr.physical_size()))
                self._fn[a].log_size_line.update(str(attr.logical_size()))

                crtime = attr.created_time().isoformat("T")
                self._fn[a].created_line.update(crtime + "Z")

                mtime = attr.modified_time().isoformat("T")
                self._fn[a].modified_line.update(mtime + "Z")

                chtime = attr.changed_time().isoformat("T")
                self._fn[a].changed_line.update(chtime + "Z")

                atime = attr.accessed_time().isoformat("T")
                self._fn[a].accessed_line.update(atime + "Z")

            except ZeroDivisionError:
                continue
        self.Layout()


class RecordDataPane(RecordPane):
    """
    Displays information about the data associated with a file.
    If the file is resident, then this displays a hex dump of the
      contents.
    If the file is non-resident, then this displays the cluster
      runs in (offset, length) sets.
    Displays each data attribute, including alternate data streams.
    TODO(wb) differentiate between ADS and main data.
    """
    def __init__(self, *args, **kwargs):
        super(RecordDataPane, self).__init__(*args, **kwargs)

    def update(self, event):
        self._sizer.Clear()
        self.DestroyChildren()

        has_runlists = False
        for attr in self._model.record().attributes():
            if attr.type() == ATTR_TYPE.DATA:
                if attr.non_resident():
                    for (_, __) in attr.runlist().runs():
                        has_runlists = True

        if has_runlists:
            warning_panel = DiskGeometryWarningPanel(self, self._model)
            self._sizer.Add(warning_panel,
                            self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

        for attr in self._model.record().attributes():
            if attr.type() == ATTR_TYPE.DATA:
                try:
                    if attr.non_resident():
                        try:
                            for (offset, length) in attr.runlist().runs():
                                runlist_panel = RunlistPanel(self,
                                                             offset,
                                                             length,
                                                             self._model)
                                self._sizer.Add(runlist_panel,
                                                0, wx.EXPAND)
                        except IndexError:
                            sys.stderr.write("Error parsing runlist\n")
                            continue
                    elif len(attr.value()) > 0:
                        value_view = wx.TextCtrl(self,
                                                 style=wx.TE_MULTILINE)
                        value_view.SetFont(wx.Font(8, wx.SWISS, wx.NORMAL,
                                                 wx.NORMAL, False, u'Courier'))
                        value_view.SetValue(unicode(_format_hex(attr.value())))
                        self._sizer.Add(value_view,
                                        self.EXPAND_VERTICALLY, wx.EXPAND)
                except ZeroDivisionError:
                    continue
        self.Layout()


class RecordAttributePane(RecordPane):
    """
    Give info about each of the attributes within an MFT record.
    """
    def __init__(self, *args, **kwargs):
        super(RecordAttributePane, self).__init__(*args, **kwargs)

    def update(self, event):
        self._sizer.Clear()
        self.DestroyChildren()

        for attr in self._model.record().attributes():
            try:
                at_view = wx.StaticBox(self, -1,
                                       "Attribute, type " + hex(attr.type()))
                at_view_sizer = wx.StaticBoxSizer(at_view, wx.VERTICAL)

                at_view_sizer.Add(LabelledLine(self, "Type", str(attr.type())),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                at_view_sizer.Add(LabelledLine(self,
                                               "Reported Name", attr.name()),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                at_view_sizer.Add(LabelledLine(self,
                                               "Type Name", attr.TYPES[attr.type()]),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

                attributes = []
                if attr.flags() & 0x01:
                    attributes.append("compressed")
                if attr.flags() & 0x4000:
                    attributes.append("encrypted")
                if attr.flags() & 0x8000:
                    attributes.append("sparse")
                if len(attributes) > 0:
                    at_view_sizer.Add(LabelledLine(self, "Attributes",
                                                   ", ".join(attributes)),
                                      self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                else:
                    at_view_sizer.Add(LabelledLine(self, "Attributes", "<none>"),
                                      self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

                at_view_sizer.Add(LabelledLine(self, "Size", str(attr.size())),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                if attr.non_resident():
                    at_view_sizer.Add(LabelledLine(self, "Resident", "False"),
                                      self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                else:
                    at_view_sizer.Add(LabelledLine(self, "Resident", "True"),
                                      self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

                sstart = attr.absolute_offset(0)
                send = attr.absolute_offset(0) + attr.size()
                data = attr._buf[sstart:send].tostring()

                data_pane = DataPane(self, -1)
                data_pane.update(data)
                at_view_sizer.Add(data_pane, self.EXPAND_VERTICALLY, wx.EXPAND)

                self._sizer.Add(at_view_sizer,
                                self.EXPAND_VERTICALLY,
                                wx.ALL | wx.EXPAND)
            except ZeroDivisionError:
                continue
        self.SetAutoLayout(1)
        self.SetupScrolling()


class RecordINDXPane(RecordPane):
    """
    If there is an INDX_ROOT attribute, show INDX records that
      can be recovered.  Note, that the INDX_ROOT attribute
      only stores active INDX records.
    If there is an INDX_ALLOCATION attribute, show the cluster
      runlists as (offset, length) tuples in the disk.
    """
    def __init__(self, *args, **kwargs):
        super(RecordINDXPane, self).__init__(*args, **kwargs)

    def update(self, event):
        self._sizer.Clear()  # Note, be sure to call self.Layout() after re-add
        self.DestroyChildren()

        if not self._model.record().is_directory():
            return

        has_runlists = False
        for attr in self._model.record().attributes():
            if attr.type() != ATTR_TYPE.INDEX_ALLOCATION:
                continue
            if attr.non_resident() != 0:
                for (_, __) in attr.runlist().runs():
                    has_runlists = True

        if has_runlists:
            warning_panel = DiskGeometryWarningPanel(self, self._model)
            self._sizer.Add(warning_panel,
                            self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

        indxroot = self._model.record().attribute(ATTR_TYPE.INDEX_ROOT)
        if indxroot and indxroot.non_resident() == 0:
            # resident indx root
            irh = IndexRootHeader(indxroot.value(), 0, False)
            for e in irh.node_header().entries():
                ir_view = wx.StaticBox(self, -1, "INDX Record Information")
                ir_view_sizer = wx.StaticBoxSizer(ir_view, wx.VERTICAL)
                ir_view_sizer.Add(LabelledLine(self, "Filename", e.filename_information().filename()),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                ir_view_sizer.Add(LabelledLine(self, "Size (bytes)", str(e.filename_information().logical_size())),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                ir_view_sizer.Add(LabelledLine(self, "Created", e.filename_information().created_time().isoformat("T") + "Z"),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                ir_view_sizer.Add(LabelledLine(self, "Modified", e.filename_information().modified_time().isoformat("T") + "Z"),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                ir_view_sizer.Add(LabelledLine(self, "Changed", e.filename_information().changed_time().isoformat("T") + "Z"),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                ir_view_sizer.Add(LabelledLine(self, "Accessed", e.filename_information().accessed_time().isoformat("T") + "Z"),
                                  self.NOT_EXPAND_VERTICALLY, wx.EXPAND)
                self._sizer.Add(ir_view_sizer,
                                self.NOT_EXPAND_VERTICALLY, wx.ALL | wx.EXPAND)
            for e in irh.node_header().slack_entries():
                ir_view = wx.StaticBox(self, -1,
                                       "Slack INDX Record Information")
                ir_view_sizer = wx.StaticBoxSizer(ir_view, wx.VERTICAL)
                ir_view_sizer.Add(LabelledLine(self, "Filename", e.filename_information().filename()), 0, wx.EXPAND)
                self._sizer.Add(ir_view_sizer,
                                self.NOT_EXPAND_VERTICALLY,
                                wx.ALL | wx.EXPAND)
        for attr in self._model.record().attributes():
            if attr.type() != ATTR_TYPE.INDEX_ALLOCATION:
                continue
            if attr.non_resident() != 0:
                # indx allocation is non-resident
                rl_view = wx.StaticBox(self, -1, "INDX_ALLOCATION Locations")
                rl_view_sizer = wx.StaticBoxSizer(rl_view, wx.VERTICAL)

                for (offset, length) in attr.runlist().runs():
                    rl_view_sizer.Add(RunlistPanel(self, offset, length, self._model),
                                      self.NOT_EXPAND_VERTICALLY,
                                      wx.EXPAND)
                self._sizer.Add(rl_view_sizer,
                                self.NOT_EXPAND_VERTICALLY,
                                wx.ALL | wx.EXPAND)
        self.SetAutoLayout(1)
        self.SetupScrolling()


class MFTRecordView(wx.Panel):
    """
    Composite view of a bunch of tabs that
      show interesting information about an MFT record.
    @param model (keyword, required) An AppModel instance.
    """
    def __init__(self, *args, **kwargs):
        self._model = kwargs.get("model", None)
        del kwargs["model"]
        super(MFTRecordView, self).__init__(*args, **kwargs)

        self._sizer = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(self._sizer)

        nb = wx.Notebook(self, -1)

        self._hex_view = RecordHexPane(nb, -1, model=self._model)
        self._meta_view = RecordMetadataPane(nb, -1, model=self._model)
        self._data_view = RecordDataPane(nb, -1, model=self._model)
        self._attrs_view = RecordAttributePane(nb, -1, model=self._model)
        self._indx_view = RecordINDXPane(nb, -1, model=self._model)

        nb.AddPage(self._hex_view,  "Hex Dump")
        nb.AddPage(self._meta_view, "Metadata")
        nb.AddPage(self._data_view, "Data")
        nb.AddPage(self._attrs_view, "Attributes")
        nb.AddPage(self._indx_view, "INDX")

        self._sizer.Add(nb, 1, wx.EXPAND)
        self._sizer.Layout()


class MFTFileView(wx.Panel):
    def __init__(self, parent, filename):
        super(MFTFileView, self).__init__(parent, -1, size=(950, 600))
        self._filename = filename
        self._model = AppModel(filename, None)

        vsplitter = wx.SplitterWindow(self, -1)

        panel_left = wx.Panel(vsplitter, -1)
        self._tree = MFTTreeCtrl(panel_left, -1, model=self._model)
        _expand_into(panel_left, self._tree)

        panel_right = wx.Panel(vsplitter, -1)
        self._recordview = MFTRecordView(panel_right, -1, model=self._model)
        _expand_into(panel_right, self._recordview)

        vsplitter.SplitVertically(panel_left, panel_right)
        vsplitter.SetSashPosition(260, True)
        _expand_into(self, vsplitter)
        self.Centre()

        self._tree.Bind(wx.EVT_TREE_SEL_CHANGED, self.OnFileSelected)

    def __del__(self, *args, **kwargs):
        self._tree.Unbind(wx.EVT_TREE_SEL_CHANGED)
        super(MFTFileView, self).__del__(*args, **kwargs)

    def OnFileSelected(self, event):
        item = event.GetItem()
        if not item.IsOk():
            item = self._tree.GetSelection()
        rec_num = self._tree.GetPyData(item)["rec_num"]

        f = NTFSFile({
            "filename": self._filename,
            "filetype": "mft",
            "offset": 0,
            "clustersize": 4096,
            "prefix": "C:",
            "progress": False,
        })

        try:
            self._model.set_record(f.mft_get_record(rec_num))
        except InvalidMFTRecordNumber as e:
            sys.stderr.write("Unable to open MFT record %d\n" % (e.value))
            return


class MFTFileViewer(wx.Frame):
    def __init__(self, parent, filename):
        super(MFTFileViewer, self).__init__(parent, -1, "MFT File Viewer",
                                            size=(900, 600))
        self.CreateStatusBar()
        self.Bind(wx.EVT_CLOSE, self.OnClose)

        menu_bar = wx.MenuBar()
        file_menu = wx.Menu()
        menu_bar.Append(file_menu, "&File")

        p = wx.Panel(self)
        self._nb = wx.Notebook(p)

        view = MFTFileView(self._nb, filename)
        self._nb.AddPage(view, filename)

        _expand_into(p, self._nb)
        self.Layout()

    def OnClose(self, event):
        sys.exit(0)

if __name__ == "__main__":
    app = wx.App(False)
    filename = sys.argv[1]
    frame = MFTFileViewer(None, filename)
    frame.Show()
    app.MainLoop()

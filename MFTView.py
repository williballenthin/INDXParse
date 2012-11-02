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
import wx
import wx.lib.scrolledpanel as scrolled
import  wx.lib.newevent

verbose = False

# RecordUpdatedEvent
# @param record The updated record.
RecordUpdatedEvent, EVT_RECORD_UPDATED_EVENT = wx.lib.newevent.NewEvent()


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
    def __init__(self, number, name, parent, is_directory):
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
    """
    def __init__(self, filename, record):
        super(AppModel, self).__init__()
        self._filename = filename
        self._nodes = {}
        self._orphans = []
        self._record = record

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

        total_count = 0
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
            Depends on the closure of `nodes` and `orphans`
            @raises RecordConflict if the record already exists in nodes
            """
            rec_num = record.mft_record_number() & 0xFFFFFFFFFFFF

            # node already exists by rec_num
            if rec_num in self._nodes:
                raise RecordConflict(rec_num)

            # no filename info --> orphan with name "???"
            fn = record.filename_information()
            if not fn:
                node = Node(rec_num, "???", None, record.is_directory())
                self._orphans.append(node)
                self._nodes[rec_num] = node
                return node

            # one level cycle
            parent_record_num = fn.mft_parent_reference() & 0xFFFFFFFFFFFF
            if parent_record_num == rec_num:
                node = Node(rec_num, fn.filename(),
                            None, record.is_directory())
                self._orphans.append(node)
                self._nodes[rec_num] = node
                return node

            if parent_record_num not in self._nodes:
                # no parent --> orphan with correct filename
                parent_buf = mftfile.mft_get_record_buf(parent_record_num)
                if parent_buf == array.array("B", ""):
                    node = Node(rec_num, fn.filename(),
                                None, record.is_directory())
                    self._orphans.append(node)
                    self._nodes[rec_num] = node
                    return node

                # parent sequence num incorrect -->
                #  orphan with correct filename
                parent = MFTRecord(parent_buf, 0, False)
                if parent.sequence_number() != fn.mft_parent_reference() >> 48:
                    node = Node(rec_num, fn.filename(),
                                None, record.is_directory())
                    self._orphans.append(node)
                    self._nodes[rec_num] = node
                    return node

                add_node(mftfile, parent)

            parent_node = self._nodes[parent_record_num]
            node = Node(rec_num, fn.filename(),
                        parent_node, record.is_directory())
            self._nodes[rec_num] = node
            parent_node.add_child(node)
            return node

        count = 0
        for record in f.record_generator():
            count += 1
            try:
                add_node(f, record)
            except RecordConflict:
                # this is expected.
                # this record must be a directory, and a descendant has already
                # been processed.
                pass
            if count % 100 == 0:
                progress_fn(count, total_count)


class MFTTreeCtrl(wx.TreeCtrl):
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
                                   style=wx.PD_AUTO_HIDE |    \
                                       wx.PD_APP_MODAL |      \
                                       wx.PD_CAN_ABORT |      \
                                       wx.PD_ELAPSED_TIME |   \
                                       wx.PD_ESTIMATED_TIME | \
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
    def __init__(self, parent, label, value):
        super(LabelledLine, self).__init__(parent, -1)
        self._sizer = wx.BoxSizer(wx.HORIZONTAL)
        self._sizer.Add(wx.StaticText(self, -1, label), 1, wx.EXPAND)
        self._text = wx.TextCtrl(self, -1, style=wx.TE_LEFT)
        self._sizer.Add(self._text, 1, wx.EXPAND)
        self.SetSizer(self._sizer)
        self.update(value)

    def update(self, value):
        self._text.SetValue(value)


class RunlistPanel(wx.Panel):
    def __init__(self, parent, offset, length):
        super(RunlistPanel, self).__init__(parent, -1)

        self._sizer = wx.BoxSizer(wx.HORIZONTAL)

        sb = wx.StaticBox(parent, -1, "Cluster Run")
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

        self.update(offset, length)

    def update(self, offset, length):
        self._base_offset_text.SetValue(str(offset))
        self._base_length_text.SetValue(str(length))
        self._cluster_offset_text.SetValue(str(32256 + offset * 4096))
        self._cluster_length_text.SetValue(str(length * 4096))

    def get_sizer(self):
        return self._sizer


def make_runlistpanel(parent, offset, length):
    pane = wx.Panel(parent, -1)
    sizer = wx.BoxSizer(wx.HORIZONTAL)

    sb = wx.StaticBox(parent, -1, "Cluster Run")
    sbs = wx.StaticBoxSizer(sb, wx.VERTICAL)

    hbox1 = wx.BoxSizer(wx.HORIZONTAL)
    hbox2 = wx.BoxSizer(wx.HORIZONTAL)
    hbox3 = wx.BoxSizer(wx.HORIZONTAL)
    hbox4 = wx.BoxSizer(wx.HORIZONTAL)
    hbox5 = wx.BoxSizer(wx.HORIZONTAL)

    hbox1.Add(wx.StaticText(pane, label="Offset (clusters)"), 1, wx.EXPAND)
    hbox1.Add(wx.TextCtrl(pane, -1, str(offset),
                          style=wx.TE_READONLY), 1, wx.EXPAND)
    hbox2.Add(wx.StaticText(pane, label="Length (clusters)"), 1, wx.EXPAND)
    hbox2.Add(wx.TextCtrl(pane, -1, str(length),
                          style=wx.TE_READONLY), 1, wx.EXPAND)
    hbox3.Add(wx.StaticText(pane, label="Offset (bytes)"), 1, wx.EXPAND)
    hbox3.Add(wx.TextCtrl(pane, -1, str(32256 + offset * 4096),
                          style=wx.TE_READONLY), 1, wx.EXPAND)
    hbox4.Add(wx.StaticText(pane, label="Length (bytes)"), 1, wx.EXPAND)
    hbox4.Add(wx.TextCtrl(pane, -1, str(length * 4096),
                          style=wx.TE_READONLY), 1, wx.EXPAND)
    hbox5.Add(wx.StaticLine(pane, -1, size=(200, 4),
                            style=wx.LI_HORIZONTAL), 1, wx.EXPAND)
    sbs.Add(hbox1, 1, wx.EXPAND)
    sbs.Add(hbox2, 1, wx.EXPAND)
    sbs.Add(hbox3, 1, wx.EXPAND)
    sbs.Add(hbox4, 1, wx.EXPAND)
    sbs.Add(hbox5, 1, wx.EXPAND)

    sizer.Add(sbs, -1, wx.EXPAND)

    pane.SetSizer(sizer)
    return pane


class RecordPane(scrolled.ScrolledPanel):
    """
    Displays some information about an MFT record.
    This is a superclass to things that might show
      interesting information.
    @param record (keyword) A record instance.
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

        self._model.Bind(EVT_RECORD_UPDATED_EVENT, self.update)

    def update(self, event):
        print "Warning: Unbound Record Pane update"


class RecordHexPane(RecordPane):
    """
    Displays a hex dump of the entire MFT record.
    @param record (keyword) A record instance.
    """
    def __init__(self, *args, **kwargs):
        super(RecordHexPane, self).__init__(*args, **kwargs)
        self._text = wx.TextCtrl(self, -1, style=wx.TE_MULTILINE)
        self._text.SetFont(wx.Font(8, wx.SWISS, wx.NORMAL,
                          wx.NORMAL, False, u'Courier'))
        self._sizer.Add(self._text, self.EXPAND_VERTICALLY, wx.EXPAND)

    def update(self, event):
        event.Skip()
        self._text.SetValue(unicode(_format_hex(self._model.record()._buf.tostring())))


class RecordMetadataPane(RecordPane):
    """
    Display metadata from the MFT record header, $SI, and $FN attributes.
    Warning, this has two pretty long methods...
    @param record (keyword) A record instance.
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
                                      "Filename Information Attribute (%s)" % \
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
        event.Skip()
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
    TODO(wb) allow custom disk geometry.
    @param record (keyword) A record instance.
    """
    def __init__(self, *args, **kwargs):
        super(RecordDataPane, self).__init__(*args, **kwargs)

    def update(self, event):
        event.Skip()
        self._sizer.Clear()  # Note, be sure to call self.Layout() after re-add
        self.DestroyChildren()

        for attr in self._model.record().attributes():
            if attr.type() == ATTR_TYPE.DATA:
                try:
                    if attr.non_resident():
                        try:
                            for (offset, length) in attr.runlist().runs():
                                runlist_panel = RunlistPanel(self, offset,
                                                             length)
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
                        self._sizer.Add(value_view, 1, wx.EXPAND)
                except ZeroDivisionError:
                    continue
        self.Layout()


class MFTRecordView(wx.Panel):
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

        nb.AddPage(self._hex_view,  "Hex Dump")
        nb.AddPage(self._meta_view, "Metadata")
        nb.AddPage(self._data_view, "Data")

        self._sizer.Add(nb, 1, wx.EXPAND)
        self._sizer.Layout()

        comment = """

        attr_view = scrolled.ScrolledPanel(nb, -1)
        attr_view_sizer = wx.BoxSizer(wx.VERTICAL)
        attr_view.SetSizer(attr_view_sizer)

        for attr in record.attributes():
            try:
                at_view = wx.StaticBox(attr_view, -1,
                                       "Attribute, type " + hex(attr.type()))
                at_view_sizer = wx.StaticBoxSizer(at_view, wx.VERTICAL)

                at_view_sizer.Add(LabelledLine(attr_view, "Type", str(attr.type())), 0, wx.EXPAND)
                name = attr.name()
                if name == "":
                    name = attr.TYPES[attr.type()]
                at_view_sizer.Add(LabelledLine(attr_view, "Name", str(name)), 0, wx.EXPAND)
                at_view_sizer.Add(LabelledLine(attr_view, "Size", str(attr.size())), 0, wx.EXPAND)

                atd_view = wx.TextCtrl(attr_view, style=wx.TE_MULTILINE)
                atd_view.SetFont(fixed_font)
                atd_view.SetValue(unicode(_format_hex(attr._buf[attr.absolute_offset(0):attr.absolute_offset(0) + attr.size()].tostring())))
                at_view_sizer.Add(atd_view, 1, wx.EXPAND)

                attr_view_sizer.Add(at_view_sizer, 1, wx.ALL|wx.EXPAND)
            except ZeroDivisionError:
                continue
        attr_view.SetAutoLayout(1)
        attr_view.SetupScrolling()
        nb.AddPage(attr_view, "Attributes")

        if record.is_directory():
            indx_panel = scrolled.ScrolledPanel(nb, -1)
            indx_panel_sizer = wx.BoxSizer(wx.VERTICAL)
            indx_panel.SetSizer(indx_panel_sizer)

            indxroot = record.attribute(ATTR_TYPE.INDEX_ROOT)
            if indxroot and indxroot.non_resident() == 0:
                # resident indx root
                irh = IndexRootHeader(indxroot.value(), 0, False)
                for e in irh.node_header().entries():
                    ir_view = wx.StaticBox(indx_panel, -1, "INDX Record Information")
                    ir_view_sizer = wx.StaticBoxSizer(ir_view, wx.VERTICAL)
                    ir_view_sizer.Add(LabelledLine(indx_panel, "Filename", e.filename_information().filename()), 0, wx.EXPAND)
                    ir_view_sizer.Add(LabelledLine(indx_panel, "Size (bytes)", str(e.filename_information().logical_size())), 0, wx.EXPAND)
                    ir_view_sizer.Add(LabelledLine(indx_panel, "Created", e.filename_information().created_time().isoformat("T") + "Z"), 0, wx.EXPAND)
                    ir_view_sizer.Add(LabelledLine(indx_panel, "Modified", e.filename_information().modified_time().isoformat("T") + "Z"), 0, wx.EXPAND)
                    ir_view_sizer.Add(LabelledLine(indx_panel, "Changed", e.filename_information().changed_time().isoformat("T") + "Z"), 0, wx.EXPAND)
                    ir_view_sizer.Add(LabelledLine(indx_panel, "Accessed", e.filename_information().accessed_time().isoformat("T") + "Z"), 0, wx.EXPAND)
                    indx_panel_sizer.Add(ir_view_sizer, 0, wx.ALL|wx.EXPAND)
                for e in irh.node_header().slack_entries():
                    ir_view = wx.StaticBox(indx_panel, -1, "Slack INDX Record Information")
                    ir_view_sizer = wx.StaticBoxSizer(ir_view, wx.VERTICAL)
                    ir_view_sizer.Add(LabelledLine(indx_panel, "Filename", e.filename_information().filename()), 0, wx.EXPAND)
                    indx_panel_sizer.Add(ir_view_sizer, 0, wx.ALL|wx.EXPAND)
            for attr in record.attributes():
                if attr.type() != ATTR_TYPE.INDEX_ALLOCATION:
                    continue
                if attr.non_resident() != 0:
                    # indx allocation is non-resident
                    for (offset, length) in attr.runlist().runs():
                        indx_panel_sizer.Add(make_runlistpanel(indx_panel, offset, length), 0, wx.EXPAND)

            indx_panel.SetAutoLayout(1)
            indx_panel.SetupScrolling()
            nb.AddPage(indx_panel, "INDX")
            """


class MFTFileView(wx.Panel):
    def __init__(self, parent, filename):
        super(MFTFileView, self).__init__(parent, -1, size=(800, 600))
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
        vsplitter.SetSashPosition(265, True)
        _expand_into(self, vsplitter)
        self.Centre()

        self._tree.Bind(wx.EVT_TREE_SEL_CHANGED, self.OnFileSelected)

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

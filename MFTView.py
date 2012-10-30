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

verbose = False


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


class MFTModel():
    def __init__(self, filename):
        self._filename = filename
        self._nodes = {}
        self._orphans = []

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
        self._record = kwargs.get("record", None)
        try:
            del kwargs["record"]
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

    def update(self, record):
        self._record = record

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
        if self._record:
            self.update(self._record)

    def update(self, record):
        self._record = record
        self._text.SetValue(unicode(_format_hex((self._record._buf.tostring()))))

class RecordMetadataPane(RecordPane):
    """

    @param record (keyword) A record instance.
    """
    def __init__(self, *args, **kwargs):
        super(RecordMetadataPane, self).__init__(*args, **kwargs)

        # note, the parent must be `self`
        record_box = wx.StaticBox(self, -1, "MFT Record")
        record_box_sizer = wx.StaticBoxSizer(record_box, wx.VERTICAL)
        # note, the parent must be `self`, not the `record_box`
        record_number = LabelledLine(self, "MFT Record Number",
                                         str(self._record.mft_record_number()))
        record_box_sizer.Add(record_number, self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

        attributes = []
        if self._record.is_directory():
            attributes.append("directory")
        else:
            attributes.append("file")
        if self._record.is_active():
            attributes.append("active")
        else:
            attributes.append("deleted")

        attributes_line = LabelledLine(self, "Attributes",
                                            ", ".join(attributes))
        record_box_sizer.Add(attributes_line, self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

        size = 0
        if not self._record.is_directory():
            data_attr = self._record.data_attribute()
            if data_attr and data_attr.non_resident() > 0:
                size = data_attr.data_size()
            else:
                size = self._record.filename_information().logical_size()

        size_line = LabelledLine(self, "Size (bytes)", str(size))
        record_box_sizer.Add(size_line, self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

        seq_line = LabelledLine(self, "Sequence Number",
                                     str(self._record.sequence_number()))
        record_box_sizer.Add(seq_line, self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

        # note, must add the sizer, not the `record_box`
        self._sizer.Add(record_box_sizer, self.NOT_EXPAND_VERTICALLY,
                        wx.EXPAND)

        si_box = wx.StaticBox(self, -1, "Standard Information Attribute")
        si_box_sizer = wx.StaticBoxSizer(si_box, wx.VERTICAL)

        attributes = []
        if self._record.standard_information().attributes() & 0x01:
            attributes.append("readonly")
        if self._record.standard_information().attributes() & 0x02:
            attributes.append("hidden")
        if self._record.standard_information().attributes() & 0x04:
            attributes.append("system")
        if self._record.standard_information().attributes() & 0x08:
            attributes.append("unused-dos")
        if self._record.standard_information().attributes() & 0x10:
            attributes.append("directory-dos")
        if self._record.standard_information().attributes() & 0x20:
            attributes.append("archive")
        if self._record.standard_information().attributes() & 0x40:
            attributes.append("device")
        if self._record.standard_information().attributes() & 0x80:
            attributes.append("normal")
        if self._record.standard_information().attributes() & 0x100:
            attributes.append("temporary")
        if self._record.standard_information().attributes() & 0x200:
            attributes.append("sparse")
        if self._record.standard_information().attributes() & 0x400:
            attributes.append("reparse-point")
        if self._record.standard_information().attributes() & 0x800:
            attributes.append("compressed")
        if self._record.standard_information().attributes() & 0x1000:
            attributes.append("offline")
        if self._record.standard_information().attributes() & 0x2000:
            attributes.append("not-indexed")
        if self._record.standard_information().attributes() & 0x4000:
            attributes.append("encrypted")
        if self._record.standard_information().attributes() & 0x10000000:
            attributes.append("has-indx")
        if self._record.standard_information().attributes() & 0x20000000:
            attributes.append("has-view-index")
        attributes_line = LabelledLine(self, "Attributes",
                                            ", ".join(attributes))
        si_box_sizer.Add(attributes_line, self.NOT_EXPAND_VERTICALLY,
                             wx.EXPAND)

        crtime = self._record.standard_information().created_time()
        created_line = LabelledLine(self, "Created", str(crtime))
        si_box_sizer.Add(created_line, self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

        mtime = self._record.standard_information().modified_time()
        modified_line = LabelledLine(self, "Modified", str(mtime))
        si_box_sizer.Add(modified_line, self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

        chtime = self._record.standard_information().changed_time()
        changed_line = LabelledLine(self, "Changed", str(chtime))
        si_box_sizer.Add(changed_line, self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

        atime = self._record.standard_information().accessed_time()
        accessed_line = LabelledLine(self, "Accessed", str(atime))
        si_box_sizer.Add(accessed_line, self.NOT_EXPAND_VERTICALLY, wx.EXPAND)

        self._sizer.Add(si_box_sizer, self.NOT_EXPAND_VERTICALLY,
                        wx.EXPAND)

        for a in self._record.attributes():
            if a.type() != ATTR_TYPE.FILENAME_INFORMATION:
                continue
            try:
                attr = FilenameAttribute(a.value(), 0, self)
                filename_type = ""
                if attr.filename_type() == 0x0:
                    filename_type = "POSIX"
                if attr.filename_type() == 0x1:
                    filename_type = "WIN32"
                if attr.filename_type() == 0x2:
                    filename_type = "DOS 8.3"
                if attr.filename_type() == 0x3:
                    filename_type = "WIN32 + DOS"

                fn_box = wx.StaticBox(self, -1,
                                      "Filename Information Attribute (%s)" % \
                                          (filename_type))
                fn_box_sizer = wx.StaticBoxSizer(fn_box, wx.VERTICAL)

                name_line = LabelledLine(self, "Filename",
                                              str(attr.filename()))
                fn_box_sizer.Add(name_line, self.NOT_EXPAND_VERTICALLY,
                                 wx.EXPAND)

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
                attributes_line = LabelledLine(self, "Attributes",
                                                    ", ".join(attributes))
                fn_box_sizer.Add(attributes_line, self.NOT_EXPAND_VERTICALLY,
                                 wx.EXPAND)

                alloc_size_line = LabelledLine(self,
                                                    "Allocated Size (bytes)",
                                                    str(attr.physical_size()))
                fn_box_sizer.Add(alloc_size_line,
                                  self.NOT_EXPAND_VERTICALLY,
                                  wx.EXPAND)

                log_size_line = LabelledLine(self,
                                                  "Logical Size (bytes)",
                                                  str(attr.logical_size()))
                fn_box_sizer.Add(log_size_line,
                                  self.NOT_EXPAND_VERTICALLY,
                                  wx.EXPAND)

                crtime = attr.created_time()
                created_line = LabelledLine(self, "Created", str(crtime))
                fn_box_sizer.Add(created_line, self.NOT_EXPAND_VERTICALLY,
                                 wx.EXPAND)

                mtime = attr.modified_time()
                modified_line = LabelledLine(self, "Modified", str(mtime))
                fn_box_sizer.Add(modified_line, self.NOT_EXPAND_VERTICALLY,
                                 wx.EXPAND)

                chtime = attr.changed_time()
                changed_line = LabelledLine(self, "Changed", str(chtime))
                fn_box_sizer.Add(changed_line, self.NOT_EXPAND_VERTICALLY,
                                 wx.EXPAND)

                atime = attr.accessed_time()
                accessed_line = LabelledLine(self, "Accessed", str(atime))
                fn_box_sizer.Add(accessed_line, self.NOT_EXPAND_VERTICALLY,
                                 wx.EXPAND)

                self._sizer.Add(fn_box_sizer, self.NOT_EXPAND_VERTICALLY,
                                wx.EXPAND)
            except Exception:
                continue

        if self._record:
            self.update(self._record)

    def update(self, record):
        self._record = record
        self._text.SetValue(unicode(_format_hex((self._record._buf.tostring()))))

class MFTRecordView(wx.Panel):
    def __init__(self, *args, **kwargs):
        self._model = kwargs.get("model", None)
        del kwargs["model"]
        super(MFTRecordView, self).__init__(*args, **kwargs)

        self._sizer = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(self._sizer)

        nb = wx.Notebook(self, -1)

        self._hex_view = RecordHexPane(nb, -1)
#        self._meta_view = RecordMetadataPane(nb, -1, record=record)

        nb.AddPage(self._hex_view, "Hex Dump")
#        nb.AddPage(self._meta_view, "Metadata")

        self._sizer.Add(nb, 1, wx.EXPAND)
        self._sizer.Layout()


    def display_record(self, record):
        self._hex_view.update(record)
#        self._meta_view.update(record)

        comment = """

        has_data = False
        data_view = wx.Panel(nb, -1)
        data_view_sizer = wx.BoxSizer(wx.VERTICAL)
        data_view.SetSizer(data_view_sizer)

        for attr in record.attributes():
            if attr.type() == ATTR_TYPE.DATA:
                try:
                    if attr.non_resident():
                        try:
                            for (offset, length) in attr.runlist().runs():
                                data_view_sizer.Add(make_runlistpanel(data_view, offset, length), 0, wx.EXPAND)
                        except IndexError:
                            sys.stderr.write("Error parsing runlist\n")
                            continue
                    else:
                        value_view = wx.TextCtrl(data_view, style=wx.TE_MULTILINE)
                        value_view.SetFont(fixed_font)
                        value_view.SetValue(unicode(_format_hex(attr.value())))
                        data_view_sizer.Add(value_view, 1, wx.EXPAND)
                    has_data = True
                except ZeroDivisionError:
                    continue
        if has_data:
            nb.AddPage(data_view, "Data")

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

    def clear_value(self):
        self._sizer.Clear()
        self._sizer.Add(wx.Panel(self, -1), 1, wx.EXPAND)
        self._sizer.Layout()


class MFTFileView(wx.Panel):
    def __init__(self, parent, filename):
        super(MFTFileView, self).__init__(parent, -1, size=(800, 600))
        self._filename = filename
        self._model = MFTModel(filename)

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
            record = f.mft_get_record(rec_num)
        except InvalidMFTRecordNumber as e:
            sys.stderr.write("Unable to open MFT record %d\n" % (e.value))
            return

        self._recordview.display_record(record)


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

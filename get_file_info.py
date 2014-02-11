from MFT import MFTEnumerator

import array
import re
import logging
import datetime

import argparse
from jinja2 import Template

from BinaryParser import Mmap
from MFT import Cache
from MFT import ATTR_TYPE
from MFT import MREF
from MFT import MSEQNO
from MFT import IndexRootHeader
from MFT import Attribute
from MFT import FilenameAttribute
from MFT import StandardInformationFieldDoesNotExist


ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~"


def ascii_strings(buf, n=4):
    reg = "([%s]{%d,})" % (ASCII_BYTE, n)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        if isinstance(match.group(), array.array):
            yield match.group().tostring().decode("ascii")
        else:
            yield match.group().decode("ascii")


def unicode_strings(buf, n=4):
    reg = b"((?:[%s]\x00){4,})" % (ASCII_BYTE)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        try:
            if isinstance(match.group(), array.array):
                yield match.group().tostring().decode("utf-16")
            else:
                yield match.group().decode("utf-16")
        except UnicodeDecodeError:
            pass


def get_flags(flags):
    """
    Get readable list of attribute flags.
    """
    attributes = []
    for flag in Attribute.FLAGS.keys():
        if flags & flag:
            attributes.append(Attribute.FLAGS[flag])
    return attributes


def create_safe_datetime(fn):
    try:
        return fn()
    except ValueError:
        return datetime.datetime(1970, 1, 1, 0, 0, 0)


def create_safe_timeline_entry(fn, type_, source, path):
    return {
        "timestamp": create_safe_datetime(fn),
        "type": type_,
        "source": source,
        "path": path,
    }


def create_safe_timeline_entries(attr, source, path):
    return [
        create_safe_timeline_entry(attr.created_time, "birthed", source, path),
        create_safe_timeline_entry(attr.accessed_time, "accessed", source, path),
        create_safe_timeline_entry(attr.modified_time, "modified", source, path),
        create_safe_timeline_entry(attr.changed_time, "changed", source, path),
    ]


def get_timeline_entries(record):
    entries = []
    si = record.standard_information()
    if si is None:
        return entries
    fn = record.filename_information()
    if fn is None:
        return entries
    filename = fn.filename()
    entries.extend(create_safe_timeline_entries(si, "$SI", filename))

    for b in record.attributes():
        if b.type() != ATTR_TYPE.FILENAME_INFORMATION:
            continue
        attr = FilenameAttribute(b.value(), 0, record)
        attr_filename = attr.filename()
        entries.extend(create_safe_timeline_entries(attr, "$FN", attr_filename))

    indxroot = record.attribute(ATTR_TYPE.INDEX_ROOT)
    if indxroot and indxroot.non_resident() == 0:
        irh = IndexRootHeader(indxroot.value(), 0, False)
        for e in irh.node_header().entries():
            fn = e.filename_information()
            fn_filename = fn.filename()
            entries.extend(create_safe_timeline_entries(fn, "INDX", fn_filename))

        for e in irh.node_header().slack_entries():
            fn = e.filename_information()
            fn_filename = fn.filename()
            entries.extend(create_safe_timeline_entries(fn, "slack-INDX", fn_filename))

    return sorted(entries, key=lambda x: x["timestamp"])


def make_filename_information_model(attr):
    if attr is None:
        return None

    return {
        "type": ["POSIX", "WIN32", "DOS 8.3", "WIN32 + DOS 8.3"][attr.filename_type()],
        "name": str(attr.filename()),
        "flags": get_flags(attr.flags()),
        "logical_size": attr.logical_size(),
        "physical_size": attr.physical_size(),
        "modified": create_safe_datetime(attr.modified_time),
        "accessed": create_safe_datetime(attr.accessed_time),
        "changed": create_safe_datetime(attr.changed_time),
        "created": create_safe_datetime(attr.created_time),
        "parent_ref": MREF(attr.mft_parent_reference()),
        "parent_seq": MSEQNO(attr.mft_parent_reference()),
    }


def make_standard_information_model(attr):
    if attr is None:
        return None
#    if attr is None:
#        default_time = datetime.datetime(1970, 1, 1, 0, 0, 0)
#        return {
#            "created": default_time,
#            "modified": default_time,
#            "changed": default_time,
#            "accessed": default_time,
#            "owner_id": 0,
#            "security_id": "",
#            "quota_charged": 0,
#            "usn": 0
#        }
    ret = {
        "created": create_safe_datetime(attr.created_time),
        "modified": create_safe_datetime(attr.modified_time),
        "changed": create_safe_datetime(attr.changed_time),
        "accessed": create_safe_datetime(attr.accessed_time),
        "flags": get_flags(attr.attributes())
    }

    # since the fields are sequential, we can handle an exception half way through here
    #  and then ignore the remaining items. Dont have to worry about individual try/catches
    try:
        ret["owner_id"] = attr.owner_id()
        ret["security_id"] = attr.security_id()
        ret["quota_charged"] = attr.quota_charged()
        ret["usn"] = attr.usn()
    except StandardInformationFieldDoesNotExist:
        pass

    return ret


def make_attribute_model(attr):
    ret = {
        "type": Attribute.TYPES[attr.type()],
        "name": attr.name(),
        "flags": get_flags(attr.flags()),
        "is_resident": attr.non_resident() == 0,
        "data_size": 0,
        "allocated_size": 0,
        "value_size": 0,
        "runs": [],
    }

    if attr.non_resident() > 0:
        ret["data_size"] = attr.data_size()
        ret["allocated_size"] = attr.allocated_size()

        if attr.allocated_size() > 0:
            for (offset, length) in attr.runlist().runs():
                ret["runs"].append({
                    "offset": offset,
                    "length": length,
                })
    else:
        ret["value_size"] = attr.value_length()
    return ret


def make_model(record, path):
    active_data = record.active_data()
    slack_data = record.slack_data()
    model = {
        "magic": record.magic(),
        "path": path,
        "inode": record.inode,
        "is_active": record.is_active(),
        "is_directory": record.is_directory(),
        "size": 0,  # updated below
        "standard_information": make_standard_information_model(record.standard_information()),
        "filename_information": make_filename_information_model(record.filename_information()),
        "owner_id": 0,  # updated below
        "security_id": 0,  # updated below
        "quota_charged": 0,  # updated below
        "usn": 0,  # updated below
        "filenames": [],
        "attributes": [],
        "indx_entries": [],
        "slack_indx_entries": [],
        "timeline": get_timeline_entries(record),
        "active_ascii_strings": ascii_strings(active_data),
        "active_unicode_strings": unicode_strings(active_data),
        "slack_ascii_strings": ascii_strings(slack_data),
        "slack_unicode_strings": unicode_strings(slack_data),
        }

    if not record.is_directory():
        data_attr = record.data_attribute()
        if data_attr and data_attr.non_resident() > 0:
            model["size"] = data_attr.data_size()
        elif record.filename_information() is not None:
            model["size"] = record.filename_information().logical_size()            
        else:
            model["size"] = 0

    for b in record.attributes():
        if b.type() != ATTR_TYPE.FILENAME_INFORMATION:
            continue
        attr = FilenameAttribute(b.value(), 0, record)
        model["filenames"].append(make_filename_information_model(attr))

    for b in record.attributes():
        model["attributes"].append(make_attribute_model(b))

    indxroot = record.attribute(ATTR_TYPE.INDEX_ROOT)
    if indxroot and indxroot.non_resident() == 0:
        irh = IndexRootHeader(indxroot.value(), 0, False)
        for e in irh.node_header().entries():
            m = make_filename_information_model(e.filename_information())
            m["inode"] = MREF(e.mft_reference())
            m["sequence_num"] = MSEQNO(e.mft_reference())
            model["indx_entries"].append(m)

        for e in irh.node_header().slack_entries():
            m = make_filename_information_model(e.filename_information())
            m["inode"] = MREF(e.mft_reference())
            m["sequence_num"] = MSEQNO(e.mft_reference())
            model["slack_indx_entries"].append(m)
    return model


def format_record(record, path):
    template = Template(
"""\
MFT Record: {{ record.inode }}
Path: {{ record.path }}
Metadata:
  Active: {{ record.is_active }}
{% if record.is_directory %}\
  Type: directory\
{% else %}\
  Type: file\
{% endif %}
  Flags: {{ record.standard_information.flags|join(', ') }}
  $SI Modified: {{ record.standard_information.modified }}
  $SI Accessed: {{ record.standard_information.accessed }}
  $SI Changed: {{ record.standard_information.changed }}
  $SI Birthed: {{ record.standard_information.created }}
  Owner ID: {{ record.standard_information.owner_id }}
  Security ID: {{ record.standard_information.security_id }}
  Quota charged: {{ record.standard_information.quota_charged }}
  USN: {{ record.standard_information.usn }}
Filenames: \
{% for filename in record.filenames %}
  Type: {{ filename.type }}
    Name: {{ filename.name }}
    Flags: {{ filename.flags|join(', ') }}
    Logical size: {{ filename.logical_size }}
    Physical size: {{ filename.physical_size }}
    Modified: {{ filename.modified }}
    Accessed: {{ filename.accessed }}
    Changed: {{ filename.changed }}
    Birthed: {{ filename.created }}
    Parent reference: {{ filename.parent_ref }}
    Parent sequence number: {{ filename.parent_seq }}\
{% endfor %}
Attributes: \
{% for attribute in record.attributes %}
  Type: {{ attribute.type }}
    Name: {{ attribute.name }}
    Flags: {{ attribute.flags|join(', ') }}
    Resident: {{ attribute.is_resident }}
    Data size: {{ attribute.data_size }}
    Allocated size: {{ attribute.allocated_size }}
    Value size: {{ attribute.value_size }} \
    {% if attribute.runs %}
    Data runs: {% for run in attribute.runs %}
      Offset (clusters): {{ run.offset }} Length (clusters): {{ run.length }} \
    {% endfor %}\
    {% endif %}\
{% endfor %}
INDX root entries:\
{% if not record.indx_entries %}\
 <none>\
{% endif %}\
{% for indx in record.indx_entries %}
  Name: {{ indx.filename }}
    Size: {{ indx.size }}
    Modified: {{ indx.modified }}
    Accessed: {{ indx.accessed }}
    Changed: {{ indx.changed }}
    Birthed: {{ indx.created }}
    Reference: {{ indx.inode }}
    Sequence number: {{ indx.sequence_num }}\
{% endfor %}
INDX root slack entries:\
{% if not record.slack_indx_entries %}\
 <none>\
{% endif %}\
{% for indx in record.slack_indx_entries %}
  Name: {{ indx.filename }}
    Size: {{ indx.size }}
    Modified: {{ indx.modified }}
    Accessed: {{ indx.accessed }}
    Changed: {{ indx.changed }}
    Birthed: {{ indx.created }}
    Reference: {{ indx.inode }}
    Sequence number: {{ indx.sequence_num }}\
{% endfor %}
Timeline:
{% for entry in record.timeline %}\
  {{ "%-30s%-12s%-8s%s"|format(entry.timestamp, entry.type, entry.source, entry.path) }}
{% endfor %}\
Active strings:
  ASCII strings:
{% for string in record.active_ascii_strings %}\
    {{ string }}
{% endfor %}\
  Unicode strings:
{% for string in record.active_unicode_strings %}\
    {{ string }}
{% endfor %}\
Slack strings:
  ASCII strings:
{% for string in record.slack_ascii_strings %}\
    {{ string }}
{% endfor %}\
  Unicode strings:
{% for string in record.slack_unicode_strings %}\
    {{ string }}
{% endfor %}\
""")
    return template.render(record=make_model(record, path))


def print_indx_info(record, path):
    print format_record(record, path)


def main():
    parser = argparse.ArgumentParser(description='Inspect '
                                     'a given MFT file record.')
    parser.add_argument('-a', action="store", metavar="cache_size", type=int,
                        dest="cache_size", default=1024,
                        help="Size of cache.")
    parser.add_argument('-p', action="store", metavar="prefix",
                        nargs=1, dest="prefix", default="\\.",
                        help="Prefix paths with `prefix` rather than \\.\\")
    parser.add_argument('-v', action="store_true", dest="verbose",
                        help="Print debugging information")
    parser.add_argument('mft', action="store",
                        help="Path to MFT")
    parser.add_argument('record_or_path', action="store",
                        help="MFT record or file path to inspect")

    results = parser.parse_args()

    if results.verbose:
        logging.basicConfig(level=logging.DEBUG)

    with Mmap(results.mft) as buf:
        record_cache = Cache(results.cache_size)
        path_cache = Cache(results.cache_size)

        enum = MFTEnumerator(buf,
                             record_cache=record_cache,
                             path_cache=path_cache)
        try:
            record_num = int(results.record_or_path)
            record = enum.get_record(record_num)
            path = results.prefix + enum.get_path(record)
            print_indx_info(record, path)
        except ValueError:
            path = results.record_or_path
            record = enum.get_record_by_path(path)
            print_indx_info(record, results.prefix + path)

if __name__ == "__main__":
    main()

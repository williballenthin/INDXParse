from MFT import MFTEnumerator

import array
import re
import logging

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


def get_timeline_entries(record):
    entries = []
    si = record.standard_information()
    fn = record.filename_information()
    filename = fn.filename()
    entries.append({
        "timestamp": si.created_time(),
        "type": "birthed",
        "source": "$SI",
        "path": filename,
    })
    entries.append({
        "timestamp": si.accessed_time(),
        "type": "accessed",
        "source": "$SI",
        "path": filename,
    })
    entries.append({
        "timestamp": si.modified_time(),
        "type": "modified",
        "source": "$SI",
        "path": filename,
    })
    entries.append({
        "timestamp": si.changed_time(),
        "type": "changed",
        "source": "$SI",
        "path": filename,
    })

    for b in record.attributes():
        if b.type() != ATTR_TYPE.FILENAME_INFORMATION:
            continue
        attr = FilenameAttribute(b.value(), 0, record)
        attr_filename = attr.filename()
        entries.append({
            "timestamp": attr.created_time(),
            "type": "birthed",
            "source": "$FN",
            "path": attr_filename,
        })
        entries.append({
            "timestamp": attr.accessed_time(),
            "type": "accessed",
            "source": "$FN",
            "path": attr_filename,
        })
        entries.append({
            "timestamp": attr.modified_time(),
            "type": "modified",
            "source": "$FN",
            "path": attr_filename,
        })
        entries.append({
            "timestamp": attr.changed_time(),
            "type": "changed",
            "source": "$FN",
            "path": attr_filename,
        })

    indxroot = record.attribute(ATTR_TYPE.INDEX_ROOT)
    if indxroot and indxroot.non_resident() == 0:
        irh = IndexRootHeader(indxroot.value(), 0, False)
        for e in irh.node_header().entries():
            fn = e.filename_information
            fn_filename = fn.filename()
            entries.append({
                "timestamp": fn.created_time(),
                "type": "birthed",
                "source": "INDX",
                "path": fn_filename
            })
            entries.append({
                "timestamp": fn.accessed_time(),
                "type": "accessed",
                "source": "INDX",
                "path": fn_filename
            })
            entries.append({
                "timestamp": fn.modified_time(),
                "type": "modified",
                "source": "INDX",
                "path": fn_filename
            })
            entries.append({
                "timestamp": fn.changed_time(),
                "type": "changed",
                "source": "INDX",
                "path": fn_filename
            })

        for e in irh.node_header().slack_entries():
            fn = e.filename_information
            fn_filename = fn.filename()
            entries.append({
                "timestamp": fn.created_time(),
                "type": "birthed",
                "source": "slack-INDX",
                "path": fn_filename
            })
            entries.append({
                "timestamp": fn.accessed_time(),
                "type": "accessed",
                "source": "slack-INDX",
                "path": fn_filename
            })
            entries.append({
                "timestamp": fn.modified_time(),
                "type": "modified",
                "source": "slack-INDX",
                "path": fn_filename
            })
            entries.append({
                "timestamp": fn.changed_time(),
                "type": "changed",
                "source": "slack-INDX",
                "path": fn_filename
            })
    return sorted(entries, key=lambda x: x["timestamp"])


def make_model(record, path, record_buf):
    si = record.standard_information()
    model = {
        "magic": record.magic(),
        "path": path,
        "record_num": str(record.mft_record_number()),
        "is_active": record.is_active(),
        "is_directory": record.is_directory(),
        "size": 0,  # updated below
        "flags": get_flags(si.attributes()),
        "created": si.created_time(),
        "modified": si.modified_time(),
        "changed": si.changed_time(),
        "accessed": si.accessed_time(),
        "owner_id": 0,  # updated below
        "security_id": 0,  # updated below
        "quota_charged": 0,  # updated below
        "usn": 0,  # updated below
        "filenames": [],
        "attributes": [],
        "indx_entries": [],
        "slack_indx_entries": [],
        "timeline": get_timeline_entries(record),
        "ascii_strings": ascii_strings(record_buf),
        "unicode_strings": unicode_strings(record_buf),
        }

    if not record.is_directory():
        data_attr = record.data_attribute()
        if data_attr and data_attr.non_resident() > 0:
            model["size"] = data_attr.data_size()
        else:
            model["size"] = record.filename_information().logical_size()

    # since the fields are sequential, we can handle an exception half way through here
    #  and then ignore the remaining items. Dont have to worry about individual try/catches
    try:
        model["owner_id"] = si.owner_id()
        model["security_id"] = si.security_id()
        model["quota_charged"] = si.quota_charged()
        model["usn"] = si.usn()
    except StandardInformationFieldDoesNotExist:
        pass

    for b in record.attributes():
        if b.type() != ATTR_TYPE.FILENAME_INFORMATION:
            continue
        attr = FilenameAttribute(b.value(), 0, record)
        model["filenames"].append({
            "type": ["POSIX", "WIN32", "DOS 8.3", "WIN32 + DOS 8.3"][attr.filename_type()],
            "name": str(attr.filename()),
            "flags": get_flags(attr.flags()),
            "logical_size": attr.logical_size(),
            "physical_size": attr.physical_size(),
            "modified": attr.modified_time(),
            "accessed": attr.accessed_time(),
            "changed": attr.changed_time(),
            "created": attr.created_time(),
            "parent_ref": MREF(attr.mft_parent_reference()),
            "parent_seq": MSEQNO(attr.mft_parent_reference()),
        })

    for b in record.attributes():
        attribute_model = {
            "type": Attribute.TYPES[b.type()],
            "name": b.name() or "<none>",
            "flags": get_flags(attr.flags()),
            "is_resident": b.non_resident() == 0,
            "data_size": 0,
            "allocated_size": 0,
            "value_size": 0,
            "runs": [],
        }

        if b.non_resident() > 0:
            attribute_model["data_size"] = b.data_size()
            attribute_model["allocated_size"] = b.allocated_size()

            if b.allocated_size() > 0:
                for (offset, length) in b.runlist().runs():
                    attribute_model["runs"].append({
                        "offset": offset,
                        "length": length,
                    })
        else:
            attribute_model["value_size"] = b.value_length()
        model["attributes"].append(attribute_model)

    indxroot = record.attribute(ATTR_TYPE.INDEX_ROOT)
    if indxroot and indxroot.non_resident() == 0:
        irh = IndexRootHeader(indxroot.value(), 0, False)
        for e in irh.node_header().entries():
            fn = e.filename_information()
            model["indx_entries"].append({
                "filename": fn.filename(),
                "size": fn.logical_size(),
                "modified": fn.modified_time(),
                "accessed": fn.accessed_time(),
                "changed": fn.changed_time(),
                "created": fn.created_time(),
                "record_num": MREF(e.mft_reference()),
                "sequence_num": MSEQNO(e.mft_reference()),
            })

        for e in irh.node_header().slack_entries():
            fn = e.filename_information()
            model["slack_indx_entries"].append({
                "filename": fn.filename(),
                "size": fn.logical_size(),
                "modified": fn.modified_time(),
                "accessed": fn.accessed_time(),
                "changed": fn.changed_time(),
                "created": fn.created_time(),
                "record_num": MREF(e.mft_reference()),
                "sequence_num": MSEQNO(e.mft_reference()),
            })

    return model


def format_record(record, path, record_buf):
    template = Template(
"""\
MFT Record: {{ record.record_num }}
Path: {{ record.path }}
Metadata:
  Active: {{ record.is_active }}
{% if record.is_directory %}\
  Type: directory\
{% else %}\
  Type: file\
{% endif %}
  Flags: {{ record.flags|join(', ') }}
  $SI Modified: {{ record.modified }}
  $SI Accessed: {{ record.accessed }}
  $SI Changed: {{ record.changed }}
  $SI Birthed: {{ record.created }}
  Owner ID: {{ record.owner_id }}
  Security ID: {{ record.security_id }}
  Quota charged: {{ record.quota_charged }}
  USN: {{ record.usn }}
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
    Reference: {{ indx.record_num }}
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
    Reference: {{ indx.record_num }}
    Sequence number: {{ indx.sequence_num }}\
{% endfor %}
Timeline:
{% for entry in record.timeline %}\
  {{ "%-30s%-12s%-8s%s"|format(entry.timestamp, entry.type, entry.source, entry.path) }}
{% endfor %}\
ASCII strings:
{% for string in record.ascii_strings %}\
  {{ string }}
{% endfor %}\
Unicode strings:
{% for string in record.unicode_strings %}\
  {{ string }}
{% endfor %}\
""")
    return template.render(record=make_model(record, path, record_buf))


def print_indx_info(record, path, record_buf):
    print format_record(record, path, record_buf)


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
            record_buf = enum.get_record_buf(record_num)
            path = results.prefix + enum.get_path(record)
            print_indx_info(record, path, record_buf)
        except ValueError:
            path = results.record_or_path
            record = enum.get_record_by_path(path)
            record_buf = enum.get_record_buf(record.mft_record_number())
            print_indx_info(record, results.prefix + path, record_buf)

if __name__ == "__main__":
    main()

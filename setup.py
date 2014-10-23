from distutils.core import setup
import INDXParse

setup(name='INDXParse',
    author='Willi Ballenthin',
    version=INDXParse.__version__,
    install_requires=[
        'wxPython',
        'jinja2',
        'fuse-python',
    ],
    py_modules=[
        'MFT',
        'get_file_info',
        'BinaryParser',
        'FileMap',
        'SortedCollection',
        'SDS',
        'Progress',
    ],
    scripts=[
        'extract_mft_record_slack.py',
        'fuse-mft.py',
        'get_file_info.py',
        'INDXParse.py',
        'list_mft.py',
        'MFTINDX.py',
        'MFTView.py',
        'SDS_get_index.py',
        'tree_mft.py',
    ],
)

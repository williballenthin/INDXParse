#!/usr/bin/make -f

# Portions of this file contributed by NIST are governed by the
# following statement:
#
# This software was developed at the National Institute of Standards
# and Technology by employees of the Federal Government in the course
# of their official duties.  Pursuant to Title 17 Seciton 105 of the
# United States Code, this software is not subject to copyright
# protection within the United States.  NIST assumes no responsibility
# whatsoever for its use by other parties, and makes no guarantees,
# expressed or implied, about its quality, reliability, or any other
# characteristic.
#
# We would appreciate acknowledgement if the software is used.

SHELL := /bin/bash

top_srcdir := $(shell cd ../.. ; pwd)

7_ntfs_undel_dd_mft := $(top_srcdir)/third_party/7-ntfs-undel.dd.mft

all: \
  7-ntfs-undel.dd.mft.txt

7-ntfs-undel.dd.mft.txt: \
  $(7_ntfs_undel_dd_mft) \
  $(top_srcdir)/.venv.done.log \
  $(top_srcdir)/indxparse/BinaryParser.py \
  $(top_srcdir)/indxparse/MFT.py \
  $(top_srcdir)/indxparse/Progress.py \
  $(top_srcdir)/indxparse/tree_mft.py
	rm -f _$@
	source $(top_srcdir)/venv/bin/activate \
	  && tree_mft.py \
	    $< \
	    > _$@
	mv _$@ $@

check: \
  all

clean:
	@rm -f \
	  *.txt \
	  _*

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

7_ntfs_undel_dd := $(top_srcdir)/third_party/7-undel-ntfs/7-ntfs-undel.dd

all: \
  7-ntfs-undel.dd.bodyfile \
  7-ntfs-undel.dd.json

7-ntfs-undel.dd.bodyfile: \
  $(7_ntfs_undel_dd) \
  $(top_srcdir)/.venv.done.log \
  $(top_srcdir)/indxparse/list_mft.py
	rm -f _$@
	source $(top_srcdir)/venv/bin/activate \
	  && list_mft.py \
	    $< \
	    > _$@
	mv _$@ $@

7-ntfs-undel.dd.json: \
  $(7_ntfs_undel_dd) \
  $(top_srcdir)/.venv.done.log \
  $(top_srcdir)/indxparse/list_mft.py
	rm -f __$@ _$@
	source $(top_srcdir)/venv/bin/activate \
	  && list_mft.py \
	    --json \
	    $< \
	    > __$@
	python3 -m json.tool \
	  __$@ \
	  _$@
	rm __$@
	mv _$@ $@

check: \
  all

clean:
	@rm -f \
	  *.bodyfile \
	  *.json \
	  _*

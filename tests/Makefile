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

all: \
  all-console_scripts

.PHONY: \
  all-MFTINDX \
  all-console_scripts \
  all-list_mft \
  all-tree_mft

all-MFTINDX:
	$(MAKE) \
	  --directory MFTINDX

# TODO: This list of unimplemented tests lines up with setup.cfg.
# * all-INDXParse
# * all-MFTView
# * all-SDS_get_index
# * all-extract_mft_record_slack
# * all-fuse-mft
# * all-get_file_info
all-console_scripts: \
  all-list_mft \
  all-tree_mft \
  all-MFTINDX

all-list_mft:
	$(MAKE) \
	  --directory list_mft

all-tree_mft:
	$(MAKE) \
	  --directory tree_mft

check: \
  all

clean:
	@$(MAKE) \
	  --directory MFTINDX \
	  clean
	@$(MAKE) \
	  --directory tree_mft \
	  clean
	@$(MAKE) \
	  --directory list_mft \
	  clean

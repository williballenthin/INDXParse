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
  .7-undel-ntfs.zip.done.log \
  7-ntfs-undel.dd.mft

.PRECIOUS: \
  7-undel-ntfs.zip

.7-undel-ntfs.zip.done.log: \
  7-undel-ntfs.zip
	rm -rf 7-undel-ntfs
	unzip $<
	# Verify hashes of test disk image.
	test \
	  "x$$(openssl dgst -md5 7-undel-ntfs/7-ntfs-undel.dd | awk '{print($$NF)}')" \
	  == \
	  "x$$(head -n1 7-ntfs-undel.dd.md5)"
	test \
	  "x$$(openssl dgst -sha256 7-undel-ntfs/7-ntfs-undel.dd | awk '{print($$NF)}')" \
	  == \
	  "x$$(head -n1 7-ntfs-undel.dd.sha2-256)"
	test \
	  "x$$(openssl dgst -sha3-256 7-undel-ntfs/7-ntfs-undel.dd | awk '{print($$NF)}')" \
	  == \
	  "x$$(head -n1 7-ntfs-undel.dd.sha3-256)"
	touch $@

# This file was originally extracted from 7-undel-ntfs.zip's contents,
# using The SleuthKit 4.12.1's icat with this command:
#
#     icat 7-undel-ntfs.zip/7-ntfs-undel.dd 0 > 7-ntfs-undel.dd.mft
#
# To avoid adding build or test dependencies, the extracted file and its
# hashes are stored in this repository.  The file was gzip'd using the
# Python gzip module, symmetrically to the module's usage in this
# recipe:
#
#     python3 -m gzip --best 7-ntfs-undel.dd.mft > 7-ntfs-undel.dd.mft.gz
#
# The initial file-copy operation is because the "gunzip" mode of the
# Python gzip module takes "$x.gz" and creates "$x", leaving "$x.gz" in
# place and printing nothing to stdout.  (I.e. there is no equivalent to
# "gunzip --to-stdout $x.gz > $x".)
7-ntfs-undel.dd.mft: \
  7-ntfs-undel.dd.mft.gz
	test -r $@.sha2-256 \
	  || (echo "ERROR:third_party/Makefile:Recorded SHA2-256 hash not found." >&2 ; exit 1)
	test -r $@.sha3-256 \
	  || (echo "ERROR:third_party/Makefile:Recorded SHA3-256 hash not found." >&2 ; exit 1)
	cp \
	  $< \
	  _$@.gz
	python3 -m gzip \
	  --decompress \
	  _$@.gz
	rm _$@.gz
	test \
	  "x$$(openssl dgst -sha256 _$@ | awk '{print($$NF)}')" \
	  == \
	  "x$$(head -n1 $@.sha2-256)"
	test \
	  "x$$(openssl dgst -sha3-256 _$@ | awk '{print($$NF)}')" \
	  == \
	  "x$$(head -n1 $@.sha3-256)"
	mv _$@ $@

# This zip file is part of a dataset with this home page:
# https://dftt.sourceforge.net/test7/index.html
7-undel-ntfs.zip:
	test -r $@.sha2-256 \
	  || (echo "ERROR:third_party/Makefile:Recorded SHA2-256 hash not found." >&2 ; exit 1)
	test -r $@.sha3-256 \
	  || (echo "ERROR:third_party/Makefile:Recorded SHA3-256 hash not found." >&2 ; exit 1)
	# Verify hashes of downloaded zip.
	wget \
	  --output-document _$@ \
	  https://prdownloads.sourceforge.net/dftt/7-undel-ntfs.zip?download
	test \
	  "x$$(openssl dgst -sha256 _$@ | awk '{print($$NF)}')" \
	  == \
	  "x$$(head -n1 $@.sha2-256)"
	test \
	  "x$$(openssl dgst -sha3-256 _$@ | awk '{print($$NF)}')" \
	  == \
	  "x$$(head -n1 $@.sha3-256)"
	mv _$@ $@

check: \
  .7-undel-ntfs.zip.done.log \
  7-ntfs-undel.dd.mft

clean:
	@rm -f \
	  *.mft \
	  .*.done.log
	@rm -rf \
	  7-undel-ntfs

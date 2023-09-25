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

PYTHON3 ?= python3

all:

.PHONY: \
  check-mypy \
  check-third_party

.venv.done.log: \
  setup.cfg \
  setup.py
	rm -rf venv
	$(PYTHON3) -m venv venv
	source venv/bin/activate \
	  && pip install \
	    --upgrade \
	    pip \
	    setuptools \
	    wheel
	source venv/bin/activate \
	  && pip install \
	    --editable \
	    .[testing]
	touch $@

check: \
  check-mypy \
  check-third_party
	$(MAKE) \
	  --directory tests \
	  check

check-mypy: \
  .venv.done.log
	source venv/bin/activate \
	  && mypy \
	    indxparse
	source venv/bin/activate \
	  && mypy \
	    --strict \
	    indxparse/INDXFind.py \
	    indxparse/MFTINDX.py \
	    indxparse/__init__.py \
	    indxparse/list_mft.py

check-third_party:
	$(MAKE) \
	  --directory third_party \
	  check

clean:
	@$(MAKE) \
	  --directory tests \
	  clean
	@$(MAKE) \
	  --directory third_party \
	  clean
	@rm -f \
	  .venv.done.log

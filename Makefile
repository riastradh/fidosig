default-target: all
default-target: .PHONY
.PHONY:

PYTHON = python

FETCH = curl -L -o

all: .PHONY
	rm -rf build && \
	$(PYTHON) setup.py build

publicsuffix: .PHONY
	$(FETCH) data/public_suffix_list.dat \
		https://publicsuffix.org/list/public_suffix_list.dat

lint: .PHONY
	$(PYTHON) -m flake8 src test

check: .PHONY
check: all
check: lint
	PYTHONPATH=`pwd`/build/lib \
	$(PYTHON) -m pytest --pyargs fidosig

clean: .PHONY
	-rm -rf build
	-rm -rf dist
	-rm -rf fidosig.egg-info

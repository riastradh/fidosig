default-target: all
default-target: .PHONY
.PHONY:

PYTHON = python3

all: .PHONY
	rm -rf build && \
	$(PYTHON) setup.py build

sdist: .PHONY
	$(PYTHON) setup.py sdist

lint: .PHONY
	$(PYTHON) -m flake8 src test

check: .PHONY
check: all
check: lint
	PYTHONPATH="`pwd`/build/lib" \
	$(PYTHON) -m pytest --pyargs fidosig

env: .PHONY
	PYTHONPATH="`pwd`/build/lib" \
	PYTHON="$(PYTHON)" \
	FIDOSIG="$(PYTHON) -m fidosig" \
	$(SHELL)

clean: .PHONY
	-rm -rf build
	-rm -rf dist
	-rm -rf fidosig.egg-info

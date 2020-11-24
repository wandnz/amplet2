EXTRA_DIST=setup.py ampsave

all-local:
	set -ex; \
        for python in $(shell pyversions -s); do \
                $$python setup.py build; \
        done; \
        for python in $(shell py3versions -s); do \
                $$python setup.py build; \
        done;

# https://blog.kevin-brown.com/programming/2014/09/24/combining-autotools-and-setuptools.html
# https://dzone.com/articles/debian-packaging-python-2-and
install-exec-local:
	set -ex; \
        for python in $(shell pyversions -s); do \
                $$python $(srcdir)/setup.py install \
                    $(DEB_PYTHON_INSTALL_ARGS) \
                    --prefix=$(prefix)/ \
                    --single-version-externally-managed \
                    --root=$(DESTDIR)/ \
                    --verbose; \
                done; \
        for python in $(shell py3versions -s); do \
                $$python $(srcdir)/setup.py install \
                    $(DEB_PYTHON_INSTALL_ARGS) \
                    --prefix=$(prefix)/ \
                    --single-version-externally-managed \
                    --root=$(DESTDIR)/ \
                    --verbose; \
                done;

clean-local:
	$(PYTHON) setup.py clean --all
	-rm -rf build dist ampsave.egg-info
	-rm ampsave/tests/*_pb2.py

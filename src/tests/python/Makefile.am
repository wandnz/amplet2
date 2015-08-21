EXTRA_DIST=setup.py ampsave ampsave.tests

all-local:
	python setup.py build

# https://blog.kevin-brown.com/programming/2014/09/24/combining-autotools-and-setuptools.html
install-exec-local:
	PYTHONPATH=$(DESTDIR)/$(pythondir)/ \
        python setup.py install \
            --prefix=$(DESTDIR)/$(prefix) \
            --install-layout=deb \
            --single-version-externally-managed \
            --record $(DESTDIR)/$(pythondir)/ampsave/install_files.txt \
            --verbose

clean-local:
	python setup.py clean --all
	-rm -rf build dist ampsave.egg-info
	-rm ampsave.tests/*_pb2.py

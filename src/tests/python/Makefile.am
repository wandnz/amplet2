EXTRA_DIST=setup.py ampsave

all-local:
	python setup.py build

# https://blog.kevin-brown.com/programming/2014/09/24/combining-autotools-and-setuptools.html
install-exec-local:
	mkdir -p $(DESTDIR)/$(pythondir)/
	PYTHONPATH=$(DESTDIR)/$(pythondir)/ \
	    python setup.py install --prefix=$(DESTDIR)/$(prefix) \
            $(DEB_PYTHON_INSTALL_ARGS)

clean-local:
	python setup.py clean --all
	-rm -rf build dist ampsave.egg-info
	-rm ampsave/tests/*_pb2.py

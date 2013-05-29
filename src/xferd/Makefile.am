EXTRA_DIST=setup.py xferd

all-local:
	python setup.py build

install-exec-hook:
	python setup.py install --prefix=$(DESTDIR)/$(prefix)


# 	Copyright (c) 2012 Peter V. Saveliev
#
# 	This file is part of py9p project.
#
# 	For license agreement, please look into LICENSE file.

version ?= "1.0"
release ?= "1.0.2"
python ?= "python"

ifdef root
	override root := "--root=${root}"
endif

ifdef lib
	override lib := "--install-lib=${lib}"
endif


all:
	@echo targets: dist, install

clean:
	rm -rf dist build MANIFEST
	find . -name "*pyc" -exec rm -f "{}" \;

check:
	for i in py9p ; \
		do pep8 $$i || exit 1; \
		pyflakes $$i || exit 2; \
		done
	-2to3 py9p

setup.py:
	gawk -v version=${version} -v release=${release} -v flavor=${flavor}\
		-f configure.gawk $@.in >$@

clean-version:
	rm -f setup.py

update-version: setup.py

force-version: clean-version update-version

docs: clean force-version
	make -C docs html

dist: clean force-version
	${python} setup.py sdist

rpm: dist
	rpmbuild -ta dist/*tar.gz

install: clean force-version
	${python} setup.py install ${root} ${lib}


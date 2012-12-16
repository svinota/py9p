# Copyright (c) 2011-2012 Peter V. Saveliev
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

version ?= "1.0"
release ?= "1.0.7"
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
	for i in py9p fuse9p/fuse9p 9pfs/9pfs; \
		do pep8 $$i || exit 1; \
		pyflakes $$i || exit 2; \
		done

setup.py py9p/__init__.py:
	gawk -v version=${version} -v release=${release} -v flavor=${flavor}\
		-f configure.gawk $@.in >$@

clean-version:
	rm -f setup.py
	rm -f py9p/__init__.py

update-version: setup.py py9p/__init__.py

force-version: clean-version update-version

docs: clean force-version
	make -C docs html

dist: clean force-version
	${python} setup.py sdist

upload: clean force-version
	${python} setup.py sdist upload

rpm: dist
	rpmbuild -ta dist/*tar.gz

install: clean force-version
	${python} setup.py install ${root} ${lib}


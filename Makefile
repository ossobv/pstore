.PHONY: clean distclean isclean default dummy
.PHONY: dist doc pstore-dist django-pstore-dist pstore-full
.PHONY: test testcopyright testdjango testint testlib testpep testtodo _testtodo

default: dist

clean:
	find . -type f '(' -name '*.pyo' -or -name '*.pyc' ')' | xargs -d\\n $(RM)
	$(RM) README.txt setup.py # these are created for every *-dist rule

distclean: clean
	$(RM) -r README.rst dist

isclean:
	# Check that there are no leftover unversioned python files.
	# If there are, you should clean it up.
	# (We check this, because the setup.py will include every .py it finds
	# due to its find_package_module() function.)
	! (svn status 2>/dev/null || true) | grep '^?.*py$$'
	# These files should be created AND removed by the *-dist rules.
	test ! -f README.txt
	test ! -f setup.py

dist: doc pstore-dist django-pstore-dist pstore-full
	# Eggs are out, tgzs are in. Building sdist should do the trick, as
	# long as we hack stuff around to create a setup.py for both.

doc: README.rst
README.rst: README.md

# run the quickest tests first
test: clean testcopyright testpep testlib testint testdjango testtodo
	@printf '\n** ALL TESTS COMPLETED **\n\n'

testint:
	@printf '\n** RUNNING INTEGRATION TESTS.. THIS REQUIRES A FLUSHED EXAMPLE DB **\n\n'
	@./manage flushall  # asks if it's ok and flushes the db
	@echo
	# Import all GPG example GPG keys
	sh -c 'cat docs/examples/*.key | gpg --import; true'
	# Remove Harm secret GPG key for testing purposes
	python -c 'import gpgme;c=gpgme.Context();k=[i for i in c.keylist() if i.uids[0].email=="harm@example.com"][0];c.delete(k,1)'
	@echo
	@./docs/integrationtest.sh

testdjango:
	@printf '\n** RUNNING DJANGO TESTS **\n\n'
	@./manage test pstore --noinput  # or without 'pstore'

testlib:
	@printf '\n** RUNNING LIB UNITTESTS **\n\n'
	PYTHONPATH=`pwd` sh -c 'for x in pstorelib/*.py; do printf "\n$$x: "; python $$x; done'
	@echo

testcopyright:
	@printf '\n** SEARCHING FOR MISSING COPYRIGHT TEXT **\n\n'
	@find . -name '*.py' | xargs -d\\n grep -c ^Copyright | sed '/:0$$/!d;s/:0$$//'
	@echo

testpep:
	@printf '\n** RUNNING PEP CODE VALIDATION **\n\n'
	sh -c 'find . -name "*.py" -print0 | xargs -0 sed -i -e "s/ \+\$$//"'
	-sh -c 'find . -name "*.py" | while read x; do pep8 --ignore=E125,E128 $$x; done'
	@echo

testtodo: _testtodo
	@printf 'TOTAL: '
	@sh -c '$(MAKE) _testtodo | sed -ne "s/^[[:blank:]]*\([0-9]\+\).*/\1/p" | awk "{x+=\$$1}END{print x}"'
	@echo

_testtodo:
	@printf '\n** COUNTING TO-DO MARKS **\n\n'
	find . -type f -not -path '*/.svn/*' -and -not -path './pkg/*' -and -not -name '*.pyc' \
		-and -not -name '*.swp' -and -not -name Makefile \
		| xargs egrep 'XXX|TODO|FIXME' | sed -e 's/:.*//' | uniq -c | sort -nr
	@echo

pstore-dist: isclean README.rst
	# sdist likes a setup.py
	# TODO: add dev-r1234 style version numbers to package?
	cat setups.py | sed -e "/^if __name__ == '__main__':/,\$$d" > setup.py
	echo 'setup_pstore()' >> setup.py
	# sdist likes a reStructuredText README.txt 
	cp -n README.rst README.txt
	# do the sdist
	python setup.py sdist
	##python setup.py register # only needed once
	#python setup.py sdist upload
	# clean up
	$(RM) MANIFEST README.txt setup.py

django-pstore-dist: isclean README.rst
	# sdist likes a setup.py
	# TODO: add dev-r1234 style version numbers to package?
	cat setups.py | sed -e "/^if __name__ == '__main__':/,\$$d" > setup.py
	echo 'setup_django_pstore()' >> setup.py
	# sdist likes a reStructuredText README.txt 
	cp -n README.rst README.txt
	# do the sdist
	python setup.py sdist
	##python setup.py register # only needed once
	#python setup.py sdist upload
	# clean up
	$(RM) MANIFEST README.txt setup.py

pstore-full: dist/pstore-full-latest.tar.gz

dist/pstore-full-latest.tar.gz: dummy
	# Add all files to a single archive (always)
	sh -c 'tar zcf dist/pstore-full-latest.tar.gz `svn ls -R | while read x; do [ -f $$x ] && echo $$x; done`'

dummy:

%.rst: %.md
	# pandoc does its tricks nicely. But we need to tweak it a little bit.
	sh -c 'pandoc $< -t rst | sed -e "s/ <#[^> ]*>//g;3s/^$$/\n(_\`back to top\`)/" > $@'
	# PyPI does not like warnings/errors
	sh -c 'rst2html $@ --no-raw --strict >/dev/null || ( rm -f $@; false )'

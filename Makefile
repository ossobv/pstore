.PHONY: clean distclean isclean default dummy

FLAKE = flake8

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
	! (git status | sed -e '1,/^# Untracked/d;/^#\t.*\.py$$/!d;s/^#\t/Untracked: /' | grep .)
	# These files should be created AND removed by the *-dist rules.
	test ! -f README.txt
	test ! -f setup.py


.PHONY: dist doc

dist: doc pstore-dist django-pstore-dist pstore-full
	# Eggs are out, tgzs are in. Building sdist should do the trick, as
	# long as we hack stuff around to create a setup.py for both.

doc: README.rst
README.rst: README.md


.PHONY: pep pyclean htmlclean

pep: htmlclean makeclean pyclean

htmlclean:
	find . -name '*.html' | while read n; do \
	  min=0; \
	  sed -e 's/^\( *\).*/\1/;/^$$/d' < "$$n" | \
	  sort -u | \
	  while IFS= read l; do \
	    test $$min -eq 0 && test $${#l} -ne 4 && echo "indent: $$n (offset $${#l} is not 4)" && break; \
	    min=1; \
	    test $$(($${#l} % 4)) -ne 0 && echo "indent: $$n (indent $${#l} is not 4)" && break; \
	  done; true; \
	done

makeclean:
	sed -i -e 's/^ \{1,8\}/\t/g;s/[[:blank:]]\+$$//' Makefile

pyclean:
	@printf '\n** RUNNING PEP CODE VALIDATION **\n\n'
	@# Replace tabs with spaces, remove trailing spaces, remove trailing newlines.
	if which pepclean >/dev/null; then \
	  find . '(' -name '*.py' -o -name '*.html' -o -name '*.xml' -o -name pstore ')' \
	    -type f -print0 | xargs --no-run-if-empty -0 pepclean; \
	fi
	# @# Add vim modelines.
	# find . -name '*.py' -size +0 '!' -perm -u=x -print0 | \
	#   xargs --no-run-if-empty -0 grep -L '^# vim:' | \
	#   xargs --no-run-if-empty -d\\n \
	#     sed -i -e '1i# vim: set ts=8 sw=4 sts=4 et ai:'
	@# Use a custom --format so the path is space separated for
	@# easier copy-pasting.
	if which $(FLAKE) >/dev/null; then \
	  find . '(' -name '*.py' -o -name pstore ')' -type f -print0 | \
	    xargs --no-run-if-empty -0 $(FLAKE) --ignore=W602 \
	      --max-line-length=99 --max-complexity=12 \
	      --format='%(path)s %(row)d:%(col)d [%(code)s] %(text)s'; \
	fi; true
	@echo


.PHONY: test testcopyright testdjango testint testlib testpep testtodo _testtodo

# run the quickest tests first
test: clean testcopyright pep testlib testint testdjango testtodo
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
	@find . -type -f '(' -name '*.py' -o -name pstore ')' | \
	  xargs -d\\n grep -c ^Copyright | sed '/:0$$/!d;s/:0$$//'
	@echo

testtodo: _testtodo
	@printf 'TOTAL: '
	@sh -c '$(MAKE) _testtodo | sed -ne "s/^[[:blank:]]*\([0-9]\+\).*/\1/p" | awk "{x+=\$$1}END{print x}"'
	@echo

_testtodo:
	@printf '\n** COUNTING TO-DO MARKS **\n\n'
	git ls-files | grep -vF Makefile | xargs egrep 'XXX|TODO|FIXME' | sed -e 's/:.*//' | uniq -c | sort -nr
	@echo


.PHONY: pstore-dist django-pstore-dist pstore-full

pstore-dist: isclean README.rst
	# sdist likes a setup.py
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
	tar zcf dist/pstore-full-latest.tar.gz --no-recursion `git ls-files`

dummy:

%.rst: %.md
	# pandoc does its tricks nicely. But we need to tweak it a little bit.
	sh -c 'pandoc $< -t rst | sed -e "\
		s/ <#[^> ]*>//g; \
		3s/^$$/\n.. _\`back to top\`:\n/; \
		s/\(\`[^\`]*\`\)__/\1_/g \
		" > $@'
	# PyPI does not like warnings/errors
	# (get rst2html from python-docutils)
	sh -c 'rst2html $@ --no-raw --strict >/dev/null || ( rm -f $@; false )'

.PHONY: clean distclean isclean default dummy

FLAKE = flake8

default: dist

clean:
	find . -type f '(' -name '*.pyo' -or -name '*.pyc' ')' | xargs -d\\n $(RM)
	$(RM) setup.py # these are created for every *-dist rule

distclean: clean
	$(RM) -r dist

isclean:
	# Check that there are no leftover unversioned python files.
	# If there are, you should clean it up.
	# (We check this, because the setup.py will include every .py it finds
	# due to its find_package_module() function.)
	! (git status | sed -e '1,/^# Untracked/d;/^#\t.*\.py$$/!d;s/^#\t/Untracked: /' | grep .)
	# These files should be created AND removed by the *-dist rules.
	test ! -f setup.py


.PHONY: dist

dist: pstore-dist django-pstore-dist pstore-full
	# Eggs are out, tgzs are in. Building sdist should do the trick, as
	# long as we hack stuff around to create a setup.py for both.


.PHONY: pep pyclean htmlclean

pep: htmlclean makeclean pyclean

htmlclean:
	find pstore/ -name '*.html' | while read n; do \
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
	@printf '\n** RUNNING PEP8 CODE VALIDATION **\n\n'
	# @# Add vim modelines.
	# find . -name '*.py' -size +0 '!' -perm -u=x -print0 | \
	#   xargs --no-run-if-empty -0 grep -L '^# vim:' | \
	#   xargs --no-run-if-empty -d\\n \
	#     sed -i -e '1i# vim: set ts=8 sw=4 sts=4 et ai:'
	tox -e flake8; true
	@echo


.PHONY: test testcopyright testdjango testint testpep testtodo _testtodo

# run the quickest tests first
test: clean testcopyright pep testint testdjango testtodo
	@printf '\n** ALL TESTS COMPLETED **\n\n'

testint:
	@printf '\n** RUNNING INTEGRATION TESTS.. THIS REQUIRES A FLUSHED EXAMPLE DB **\n\n'
	@./manage flushall  # asks if it's ok and flushes the db
	@echo
	# Import all GPG example GPG keys
	sh -c 'cat docs/examples/*.key | gpg --import; true'
	# Remove Harm secret GPG key for testing purposes
	python -c 'import gpg;c=gpg.Context();k=[i for i in c.keylist() if i.uids[0].email=="harm@example.com"][0];c.op_delete_ext(k,1)'
	@echo
	@./docs/integrationtest.sh

testdjango:
	@printf '\n** RUNNING DJANGO TESTS **\n\n'
	@./manage test --noinput

testcopyright:
	@printf '\n** SEARCHING FOR MISSING COPYRIGHT TEXT **\n\n'
	@! ( find pstore/ -type f -name '*.py'; find pstorelib/ -type f -name '*.py' ) | \
	  xargs -d\\n grep -cE '^(# )?Copyright' | sed '/:0$$/!d;s/:0$$//' | \
	  while read f; do test -s "$$f" && echo "$$f"; done | grep ''
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
	# do the sdist
	python setup.py sdist
	##python setup.py register # only needed once
	#LEGACY#python setup.py sdist upload
	#twine upload dist/pstore-*.tar.gz
	# clean up
	$(RM) MANIFEST setup.py

django-pstore-dist: isclean README.rst
	# sdist likes a setup.py
	cat setups.py | sed -e "/^if __name__ == '__main__':/,\$$d" > setup.py
	echo 'setup_django_pstore()' >> setup.py
	# do the sdist
	python setup.py sdist
	##python setup.py register # only needed once
	#LEGACY#python setup.py sdist upload
	#twine upload dist/django-pstore-*.tar.gz
	# clean up
	$(RM) MANIFEST setup.py

pstore-full: dist/pstore-full-latest.tar.gz

dist/pstore-full-latest.tar.gz: dummy
	# Add all files to a single archive (always)
	tar zcf dist/pstore-full-latest.tar.gz --no-recursion $$(git ls-files)

dummy:

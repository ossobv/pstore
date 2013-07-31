pstore :: Python Protected Password Store
=========================================

Quick jump: <a id="jump" name="jump"></a>
            [File layout](#filelayout) |
            [Makefile](#makefile) |
            [FAQ/Notes](#faqnotes)

This is a developer document. This documents still needs some live.


File layout <a id="filelayout" name="filelayout"></a>
-----------------------------------------------------

    Path              | Description
    ------------------+------------
    bin/              | The pstore CLI interface.
    contrib/          | Extras for the CLI.
    docs/             | Documentation, tests and patches.
    pstore/           | The pstore backend (django application).
    pstorelib/        | The pstore shared library (used by both).
    ------------------+------------
    dist/             | Output directory for created packages.
    ------------------+------------
    CHANGES.md        | Changelog.
    CODING.md         | Coding guidelines and explanations of choices.
    Makefile          | Makefile, for testing, packaging, etc..
    MANIFEST.in       | Manifest file for python distutils.
    manage            | Django management script, OSSO-fied.
    README.md         | Instructions/readme.
    requirements.txt  | Howto/readme about the requirements (pip -r).
    setups.py         | File from which setup.py's are generated.
    TODO              | A list of items to do.


Makefile <a id="makefile" name="makefile"></a>
----------------------------------------------

    # Clean project dir
    make clean
    make distclean

    # Make dist files
    make dist

    # Run unit and integration tests
    make test


FAQ/Notes <a id="faqnotes" name="faqnotes"></a>
-----------------------------------------------

### Why do we use both multipart form uploads and binary downloads and json objects?

For short messages, the json is very convenient. For long binary messages, using
any encoding other than raw octets is rather inefficient. (25% overhead for base64
data transfers or inefficient binary decoding in json strings.)

### Why do we refer to "key" in django-pstore and not "pubkey"?

Because the django-pstore only knows about public keys.

### Do not use ordering= in the model Meta class

Django tip: try to avoid 'ordering' in the Meta class. Define it in the admin.py
instead, which is probably where you we're using it.

### MySQL has broken atomicity even inside transactions

You cannot swap two values while keeping unique key constraints.
Normally you don't want to, but it can be convenient during testing to swap
some values around. You're stuck with ugliness like this:

    set foreign_key_checks = 0;
    update pstore_property set user_id = (case user_id when 2 then -1 when 1 then -2 else user_id end);
    update pstore_property set user_id = -user_id where user_id < 0;
    set foreign_key_checks = 1;

### More stuff that needs some documentation cleanup

    ## Absolute/relative imports ##
    
    # We could use relative imports when doing intra-package imports.
    # > The submodules often need to refer to each other. For example, the surround
    # > module might use the echo module. In fact, such references are so common
    # > that the import statement *first* looks in the containing package before
    # > looking in the standard module search path.
    # http://docs.python.org/2/tutorial/modules.html#intra-package-references
    #
    # But, PEP 8 has this to say:
    # > Relative imports for intra-package imports are highly discouraged.
    # The explicit absolute import doesn't require a particular python version,
    # reduces chances for name clashes and is more readable.
    # http://www.python.org/dev/peps/pep-0008/#imports
    #
    # And PEP 328 says:
    # > from __future__ import absolute_import
    # That forces you to use explicit relative imports when needed (which is
    # rarely). You may freely remove these statements to make things work on older
    # (pre 2.5) pythons, but they force us to do the right thing while developing.
    #
    # This however *does* mean that you must add the parent directory to your
    # search path (if it isn't in a globally search path already) when you want to
    # unit test the individual modules. E.g.:
    # PYTHONPATH=`pwd` sh -c 'for x in pstorelib/*.py; do python $x; done'
    
    ## Import order ##
    
    # > Imports should be grouped in the following order:
    # > 1. standard library imports (os, sys)
    # > 2. related third party imports (Crypto, django, gpgme)
    # > 3. local application/library specific imports (pstorelib)
    # > You should put a blank line between each group of imports.
    # http://www.python.org/dev/peps/pep-0008/#imports
    
    ## Other ##
    
    # TODO: read this: http://docs.python.org/2/distutils/introduction.html
    # TODO: document and use this:
    
    #__author__ = "Rob Knight, Gavin Huttley, and Peter Maxwell"
    #__copyright__ = "Copyright 2007, The Cogent Project"
    #__credits__ = ["Rob Knight", "Peter Maxwell", "Gavin Huttley",
    #                            "Matthew Wakefield"]
    #__license__ = "GPL"
    #__version__ = "1.0.1"
    #__maintainer__ = "Rob Knight"
    #__email__ = "rob@spot.colorado.edu"
    #__status__ = "Production"

### vim: set syn=markdown:

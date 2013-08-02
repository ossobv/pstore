#!/usr/bin/env python
# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore setup -- Python Protected Password Store (setup)
Copyright (C) 2012,2013  Walter Doekes <wdoekes>, OSSO B.V.

This script is called setups.py and not setup.py. It contains two separate
setup calls, one for `pstore` and one for `django-pstore`.

During the `make dist` call, this file is copied over setup.py and the
appropriate call is appended. That way both packages get their own setup.py.
"""
import re

# TODO: comments about this...
# SAFELY IGNORE THIS WARNING. THE REQUIREMENTS GET PACKAGED!
# /usr/lib/python2.7/distutils/dist.py:267: UserWarning: Unknown distribution
# option: 'install_requires'
from distutils.core import setup
from distutils.version import LooseVersion  # strict is too ~, even for me

# TODO: see this
# See also, for metadata help:
# http://docs.python.org/2/distutils/setupscript.html#additional-meta-data
# See also, for deb/ubuntu packaging instructions:
# http://ubuntuforums.org/showthread.php?t=1002909

# TODO: add readme/manpage?

try:
    # When installing the django-pstore package before the pstore package, this
    # would fail. 
    from pstorelib import VERSION_STRING
except ImportError:
    VERSION_STRING = None


with open('CHANGES.md') as file:
    matcher = re.compile(r'^[0-9?]{4}-[0-9?]{2}-[0-9?]{2}: ([0-9].*?)\s*$')
    matches = []
    for line in file:
        match = matcher.match(line)
        if match:
            matches.append(LooseVersion(match.groups()[0]))
    # Double check that versions are in the right order
    for i in range(1, len(matches)):
        high = matches[i - 1]
        low = matches[i]
        assert high > low, ('CHANGES.md version order mismatch: %r <= %r' %
                            (high, low))
    # Double check that the last version equals the version in the pstorelib,
    # if pstorelib is installed already.
    if VERSION_STRING:
        assert matches[0] == VERSION_STRING, ('pstorelib version does not '
                                              'match CHANGES.md')
    # Fetch "current" version
    version = str(matches[0])

with open('README.txt') as file:
    long_description = file.read()

defaults = {
    'version': version,
    'author': 'Walter Doekes',
    'author_email': 'wjdoekes+pstore@osso.nl',
    'url': 'https://github.com/ossobv/pstore#jump',
    'download_url': 'https://code.osso.nl/projects/pstore/',
    'license': 'LGPLv3',
    'long_description': long_description,
    'classifiers': [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Framework :: Django',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: System Administrators',
        ('License :: OSI Approved :: GNU Lesser General Public License v3 or '
         'later (LGPLv3+)'),
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: System :: Archiving',
        'Topic :: System :: Systems Administration',
    ],
}

EXCLUDE_FILES = (
    # These contain the local settings. We include the settings.py.template
    # instead.
    ('pstore', 'settings', 'pstore/settings.py'),
)


def setup_pstore():
    setup(
        name='pstore',
        packages=['pstorelib'],
        package_data={'pstorelib': [
            'lgpl-3.0.txt',
        ]},
        scripts=[
            'bin/pstore',   # no .py suffix for executables
        ],
        install_requires=['pygpgme', 'pyasn1>=0.0.8a', 'pycrypto>=2.0.1'],

        description='Python Protected Password Store library and client',
        keywords='password encrypted sharing cli',
        **defaults
    )


def setup_django_pstore():
    # Assert that our custom module finder is used.
    global EXCLUDE_FILES_HACK
    EXCLUDE_FILES_HACK = False

    setup(
        name='django-pstore',
        packages=['pstore'],
        package_data={'pstore': [
            'lgpl-3.0.txt',
            '*.template',
            'fixtures/*',
            'templates/*.html',
        ]},
        install_requires=['Django>=1.3,<1.5', 'pstore'],

        description='Python Protected Password Store server application',
        keywords='password encrypted sharing cli',
        **defaults
    )

    if not EXCLUDE_FILES_HACK:
        import sys
        if sys.argv == ['setup.py', 'register']:
            pass
        else:
            raise RuntimeError('Included local settings! Aborting!')


# Hack to overcome deficiency in distutils/setuptools -- inability to exclude
# specific files. Modify the build process to exclude specific files from the
# build. Adapted to assert that the hack still works.
#
# Original:
# http://xylld.wordpress.com/2009/09/24/python-setuptools-workaround-for-\
#        ignore-specific-files/

from distutils.command.build_py import build_py
_find_package_modules_orig = build_py.find_package_modules


def find_package_modules(self, package, package_dir):
    # Make a note that this still works.
    global EXCLUDE_FILES_HACK
    EXCLUDE_FILES_HACK = True

    modules = _find_package_modules_orig(self, package, package_dir)
    for pkg, module, fname in EXCLUDE_FILES:
        if (pkg, module, fname) in modules:
            modules.remove((pkg, module, fname))
            print ('excluding pkg = %s, module = %s, fname = %s' %
                   (pkg, module, fname))
    return modules

build_py.find_package_modules = find_package_modules


# Hack to allow two setup() calls in the same setup.py. When called from the
# `make dist` Makefile command this bit below is replaced by either a call to
# `setup_pstore` or to `setup_django_pstore`.
if __name__ == '__main__':
    import sys
    try:
        which = sys.argv.pop(1)
    except IndexError:
        which = None
    if which == 'django-pstore':
        setup_django_pstore()
    elif which == 'pstore':
        setup_pstore()
    else:
        raise ValueError('Unexpected project supplied as first argument')

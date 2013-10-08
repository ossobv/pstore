pstore :: Python Protected Password Store
=========================================

The list of changes.


????-??-??: 1.0.3a
------------------
 * Messages to auth.log get a proper prefix.

2013-10-08: 1.0.2
-----------------
 * Fix bad exception thrown when trying to add non-existent users.
   Reported by Herman :)
 * Escape slashes in URLs not with the regular percent-encoding but
   with an equals sign instead. This was needed because the WSGI spec
   does not provide a compatible way to read the escaped URI. Now you
   can use slashes in object identifiers and property names again.
 * Remove a single trailing line feed if input comes from a TTY. Add
   a single trailing line feed if output goes to a TTY.

2013-08-02: 1.0.1
-----------------
 * Fix so django-pstore can be installed without having to install
   pstore first.

2013-07-31: 1.0
---------------
 * Move to github.

2013-07-31: 0.96
----------------
 * Fix bug with stdin not ending after a single CTRL+D.
 * Improve readability of Markdown files.
 * Clean up documentation, fix unit tests.
 * Allow the integration test to use an already running django-pstore.
   This aids in debugging problems.
 * Document how Large File issues may be solved.
 * Take version info from the CHANGES.md.
 * Use a single version number all over the project.

2013-04-15: 0.95rc4
-------------------
 * There was no changelog.
 * vim: set syntax=markdown tw=72:

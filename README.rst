pstore :: Python Protected Password Store
=========================================

.. _`back to top`:

Quick jump: _`Summary` \| `Usage examples`_ \|
`Installation`_ \| `FAQ`_

Do you want to store and share passwords? With pstore you store the
encrypted passwords on a remote server. All encryption is done locally
by the command line interface, so the server never sees your unencrypted
passwords.

Summary 
--------

(`back to top`_)

pstore allows you to store and retrieve passwords and other sensitive
data in a safe manner. The permission system allows you to share these
secrets with others on the same pstore server.

For passwords and other secret items, you encrypt them on the client
side automatically with the pstore client. This way the pstore server
never has any knowledge of the secret content, and your data is secure
(\*) even when the server is breached.

Encryption is done using GPG. One of the admins installs your public key
on the pstore server. After that you're ready to go.

(\*) Security of course depends on everyone using strong secret keys and
everyone keeping them private.

Usage examples 
---------------

(`back to top`_)

You have set your ``.pstorerc``:

::

    $ cat ~/.pstorerc 
    --store-url=https://my.pstore.server/

List all machines that contain example in the name:

::

    $ pstore example
      Machine                   User access
    ------------------------------------------------------------------------
    + new.example.com           joe, walter
    + walter.example.com        walter

List machine password for ``walter.example.com``:

::

    $ pstore walter.example.com
    ip-address = 1.2.3.4
    password = wAlTeR!

Add a new machine password, also accessible for joe:

::

    $ pstore -c walter2.example.com +joe
    Type new machine password: 
    Type new machine password again: 

    $ pstore example
      Machine                   User access
    ------------------------------------------------------------------------
    + new.example.com           joe, walter
    + walter.example.com        walter
    + walter2.example.com       joe, walter

    $ pstore walter2.example.com
    password = abc

Add a public (unencrypted) and shared (encrypted) property to the new
machine:

::

    $ printf walter2 | pstore walter2.example.com -ps ssh-username
    $ cat ssl-cert.key | pstore walter2.example.com -pe ssl-cert.key
    $ pstore walter2.example.com
    ssh-username = walter2
    ssl-cert.key = (1533 byte encrypted)
    password = abc

See the ``contrib`` directory for bash completion scripts and a *dirty
hack* to supply the password to the *ssh* client automatically.

Installation 
-------------

(`back to top`_)

Installing the pstore client is a matter of running
``pip install ./pstore-<version>.tar.gz``. This will install the
necessary requirements and install the pstore binary in your path.

Installing the pstore server is a little bit more work:

1. Install ``pstore``, the client (see above).
2. Refer to the Django project for detailed django installation
   procedures. But it should basically be something like this:

   -  Make a virtualenv (optional).
   -  Install the requirements from requirements.txt (optional, the
      django-pstore installation does this too).
   -  Install ``django-pstore``.
   -  Copy ``pstore/settings.py.template`` to ``pstore/settings.py`` and
      configure as needed. Those comfortable with Django, can choose to
      integrate it into a different project. Don't forget to set the
      ``DATABASES`` and ``SECRET_KEY`` variables.
   -  Make known where your settings are, by exporting the
      ``DJANGO_SETTINGS_PATH`` and/or ``DJANGO_SETTINGS_MODULE``
      environment variables with the right values.

3. Run ``django-admin.py syncdb``. It will create the necessary tables
   and an admin account for you.
4. Check and alter ``pstore/wsgi.py`` as needed.
5. You can now run the development server to test:
   ``django-admin.py runserver``. When you're done testing you should
   set it up on a proper webserver (nginx+uwsgi, apache+mod\_wsgi or
   whatever floats your boat). *Don't forget to tell the wsgi server
   your virtualenv path if you're using that.*

Set up users and keys:

1. If you used the supplied ``pstore/settings.py`` you'll surf to
   ``localhost:8000`` (or where the site is running). Supply your admin
   credentials.
2. Go to ``Auth -> Users``. Add users as appropriate.
3. Go to ``Pstore -> Public keys``. Add a single public key for every
   user that should be using the system. A GPG public key can be
   extracted from your keyring using
   ``gpg --export --armor my@email.addr``. The ``key`` value should look
   something like this. The ``description`` is for human consumption
   only.

   ::

       -----BEGIN PGP PUBLIC KEY BLOCK-----
       Version: GnuPG v1.4.11 (GNU/Linux)
       |
       mI0EULkssgEEAKeoPrMO5CHxoO8/KTXLA1FP2IQr4n3Og+DvsziIZ6vdcDmhtcsx
       ...
       AK968N1Yrw+ytDuus3s7xPXYAw==
       =TEm/
       -----END PGP PUBLIC KEY BLOCK-----

   If you have good reasons, you can go old style and use the SSH public
   key here, like this:

   ::

       ssh-rsa AAAAq2qMaC2...fBPcPsqMcwqsMHnBCzA= myname@myserver

   Using GPG is preferred however.

Set up the client:

1. You'll install the pstore client package on all machines that you'll
   want to connect from.
2. Set up ``~/.pstorerc``. You can put anything in there that you see in
   ``pstore --help``, but generally you'll want one or more
   ``--store-url=`` items in there. And possibly a ``--user=``.
3. Type ``pstore -c my.first.machine`` to create a password for
   *my.first.machine*.

You're ready to go. Call the pstore client with ``--help`` and
``--help --verbose`` for more help and tips.

FAQ 
----

(`back to top`_)

How do I install a downloaded tgz?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    sudo pip install ./pstore-<version>.tar.gz
    sudo pip install ./django-pstore-<version>.tar.gz

For the client you'll only need the first package.

configure: error: no acceptable C compiler found in $PATH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. or various other compile related errors when running ``pip install``.

Make sure you have a C compiler (gcc) and python development headers.

::

    sudo apt-get install build-essential
    sudo apt-get install python-dev

Or you could install the dependencies manually.

::

    # for the client and server
    sudo apt-get install python-gpgme python-pyasn1 python-crypto
    # for the server
    sudo apt-get install python-django python-mysqldb

fatal error: gpgme.h: No such file or directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pygpgme requires the libgpgme development headers.

::

    sudo apt-get install libgpgme11-dev

Couldn't find index page for 'pstore' (maybe misspelled?)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Make sure you install the ``pstore`` package before installing
``django-pstore``. This shouldn't be necessary anymore, as we've
uploaded that package to PyPI.

How do I uninstall?
~~~~~~~~~~~~~~~~~~~

Uninstalling the client package is done using *pip*:

::

    sudo pip uninstall pstore

You may need to ``rm /usr/local/bin/pstore`` manually.

For the server, you'll probably need to do more than just uninstalling
``django-pstore``. After all, you put the app in a Django project and
you created a database for it.

Note that dependencies like Django, pyasn1, pycrypto, pygpgme, aren't
uninstalled automatically.

ImportError: No module named pstorelib.bytes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When running ``./bin/pstore`` when developing, you'll need to tell it
where the packages are:

::

    export PYTHONPATH=`pwd`

NOTICE: re-using cached password
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To make the application usable, decryption passphrase information has to
be cached. Preferably, this is done using some kind of password agent
like *gpg-agent*. If such an agent is unavailable, we cache the password
in cleartext in memory for the duration of the pstore command.

The NOTICE is there to remind you that it is not as safe as it could be.

How do I make password caching agents forget my password?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Your graphical desktop environment generally starts a password caching
daemon. That could be *seahorse-agent* or *gpg-agent* or something else.

I couldn't find a way to reliably clear the *seahorse-agent* password
cache. I only found reliable ways to kill it by accident (on Ubuntu
10.04).

The *gpg-agent* (gnupg-agent package) seemed more stable. (Log out and
in after install.) Making it forget your cached passphrase is a matter
of sending it a ``SIGHUP``.

::

    pkill -HUP gpg-agent

*(If you're now wondering, like me, who then caches your decrypted
private ssh key: it's the ssh-agent, even though it's the gnome-keyring
who asked for the password. Clearing the ssh-agent cache is a matter of
doing ``ssh-add -D``.)*

crypto error: encrypt message too long
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You're probably trying to set a larger property on an object where an
sshrsa user has permissions. Either convert all users to use GPG or
upload the large property as public (unencrypted!) property.

Issues with large file support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When running the integration test, you could see something like this:

::

    * Large file support (adding large public file):
    backend error: could not connect to http://127.0.0.1:8000

      FAIL: could not write large unencrypted file
      > NOTICE: not encrypting the value

This is likely caused by apparmor(1) on the mysqld. We need read/write
permissions in /tmp.

Further, you may need to increase the ``max_allowed_packet`` to
something higher than ``16MB`` if you want to store larger files.

(`back to top`_)

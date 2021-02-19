#!/usr/bin/env python
# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore -- Python Password Protected Store
Copyright (C) 2010,2012,2013,2015,2017  Walter Doekes <wdoekes>, OSSO B.V.

    This application is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published
    by the Free Software Foundation; either version 3 of the License, or (at
    your option) any later version.

    This application is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this application; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
    USA.
"""
from __future__ import absolute_import

import errno
from io import BytesIO
import os
import sys
from getopt import GetoptError, gnu_getopt
from getpass import getpass, getuser
from tempfile import mktemp

from pstorelib import VERSION_STRING
from pstorelib.bytes import FileWithoutTrailingEnter, sendfile
from pstorelib.crypt import PStoreCrypt, CryptoWriter
from pstorelib.exceptions import (PStoreException, UserError, NotAllowed,
                                  NotFound)
from pstorelib.server import Backend


# Optional. If they don't exist, you won't notice their features.
SSH_ASKPASS_APP = '/usr/local/bin/ssh_echopass'
SSH_ASKPASS_PRELOAD = '/usr/local/lib/ssh_askpass.so'

ALPHA = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
         'abcdefghijklmnopqrstuvwxyz')
NUM = '0123456789'
ALNUM = ALPHA + NUM

bytes_stdout = sys.stdout.buffer  # py3 for raw bytes
bytes_stdin = sys.stdin.buffer


class PStoreInterface(object):
    PASSWORD_PROPERTY = 'password'

    def __init__(self, config):
        self.config = config
        self.backend = Backend(urls=config['store_urls'],
                               user=config['user'],
                               verbose=config['verbose'])

    ###########################################################################
    # SHORTCUTS
    ###########################################################################

    def add_machine(self, machine, new_password, allowed_users):
        if new_password in (None, ''):
            raise UserError('empty password rejected')
        fp = BytesIO(new_password)
        self.propset(
            machine, self.PASSWORD_PROPERTY, fp,
            allowed_users=list(set(allowed_users)),
            o_excl=True)

    def change_password(self, machine, new_password):
        if new_password in (None, ''):
            raise UserError('empty password rejected')
        fp = BytesIO(new_password)
        self.propset(
            machine, self.PASSWORD_PROPERTY, fp,
            allowed_users=True)  # <-- True means "use existing users"

    def change_permissions(self, objectid, allow, revoke):
        object = self.backend.get_object(objectid)

        users = object['users'].keys()
        # It doesn't make sense to check these on the server. The only
        # server-side check we do is on the resulting new_users list.
        if not all(i in users for i in revoke):
            raise UserError('one or more users cannot be revoked')
        if any(i in users for i in allow):
            sys.stderr.write('WARNING: one or more users already allowed\n')

        new_users = list(set(users).difference(set(revoke)).union(set(allow)))
        self.alter_permissions(objectid, new_users, object=object)

    def get_objects(self, objectid_contains, allowed_only, verbose):
        return self.backend.get_objects(objectid_contains=objectid_contains,
                                        allowed_only=allowed_only,
                                        verbose=verbose)

    def get_password(self, identifier):
        # Get object.
        object = self.backend.get_object(identifier)
        # The object fetched is already quite verbose. The password might be
        # in there already.
        property = self.PASSWORD_PROPERTY
        try:
            info = object['properties'][property]     # KeyError if not
            decrypt_with = info['data'].decrypt_with  # AttributeError if None
        except (AttributeError, KeyError):
            fp = self.propget(identifier, property)
        else:
            if info['enctype'] == 'none':
                sys.stderr.write('WARNING: password as public property?\n')
            fp = decrypt_with()

        password = fp.read()
        return password, object

    def get_properties(self, objectid, allowed_only=True):
        '''Get the available properties, possibly with contents.'''
        object = self.backend.get_object(objectid, allowed_only=allowed_only)
        return object['properties']

    def search_properties(self, allowed_only=True, propkey_icontains=None,
                          propvalue_icontains=None):
        '''Search available properties.'''
        return self.backend.propsearch(
            allowed_only=allowed_only, propkey_icontains=propkey_icontains,
            propvalue_icontains=propvalue_icontains)

    ###########################################################################
    # REGULAR INTERFACE
    ###########################################################################

    def alter_permissions(self, objectid, allowed_users, object=None):
        # 1. Get user info for the new list of allowed users.
        # (may raise NotFound, NotAllowed, NoNonce)
        keys = self.backend.get_keys(allowed_users)
        assert len(keys) == len(allowed_users)

        # 2. Get all *encrypted* properties.
        # No need to get the allowed_only=False (all the properties), because
        # getting empty/blank encrypted properties for a disallowed user
        # doesn't make it possible to alter permissions anyway. See check at
        # "if not files".
        object = object or self.backend.get_object(objectid)
        properties = {}
        for property, info in object['properties'].items():
            if info['enctype'] == 'none':
                continue
            properties[property] = self.propget(
                objectid, property.encode('ascii'))

        # FIXME: there should be a way to denote that we are not updating the
        # properties for a particular user.
        # that would allow us to only send a new list of usernames when we only
        # want to revoke; and to only send property contents for the new users.

        # 3. Re-encrypt those properties according to the new allowed users
        # list.
        files = []
        for property, fp in properties.items():
            writer = CryptoWriter(fp=fp)
            if 'PSTORE_NOINPUT' not in os.environ:
                sys.stderr.write('INFO: encrypting..\n')
            for user in allowed_users:
                encryptedfp = writer.encrypt_with(keys[user])
                files.append((
                    property.encode('ascii'), user.encode('ascii'),
                    encryptedfp))

        # 4. Check that we actually did something. All objects have at least
        # one encrypted property. If there is none, then we're looking at a
        # disallowed object.
        if not files:
            assert self.config['user'] not in keys.keys()
            raise NotAllowed()

        # 5. Upload the whole batch in a single go, along with the user
        # modifications.
        self.backend.propupd(objectid, files=files)

    def propget(self, objectid, property):
        return self.backend.propget(objectid, property)

    def propset(
            self, objectid, property, fp, allowed_users=None, o_excl=False):
        """The ``allowed_users`` argument can be one of three things:
        - ``None`` which means the property is public (unencrypted)
        - ``True`` which means: take the user list from the server. This won't
          work when creating a new objectid.
        - An explicit list with usernames.

        If allowed_users is None, the property is public (unencrypted). If
        allowed_users is True, the object should already exist: we take the
        current list of allowed users. If the object doesn't exist,
        allowed_users should be a list of usernames.
        """
        if fp.isatty():
            # When people enter stuff on the command line, they are used to
            # adding a line feed. Even though that shouldn't be in the value.
            # Remove it.
            fp = FileWithoutTrailingEnter(fp)

        if allowed_users:
            if allowed_users is True:
                # Fetch the currently allowed users list.
                data = self.backend.get_object(objectid)
                # Are we allowed to do anything?
                if self.config['user'] not in data['users'].keys():
                    # This will fail.. but we'll let the server do this check.
                    # That's where the check should happen anyway.
                    sys.stderr.write('WARNING: this will fail\n')
                # Set the allowed users list.
                allowed_users = data['users']
                del data

            # May raise UserError
            keys = self.backend.get_keys(allowed_users)
            assert len(keys) == len(allowed_users)

            # Encrypt the value.
            files = []
            writer = CryptoWriter(fp=fp)
            if 'PSTORE_NOINPUT' not in os.environ:
                sys.stderr.write('INFO: encrypting..\n')
            for user in allowed_users:
                encryptedfp = writer.encrypt_with(keys[user])
                files.append((
                    property.encode('ascii'), user.encode('ascii'),
                    encryptedfp))
        else:
            # The value is public.
            files = [(property.encode('ascii'), b'*', fp)]

        # FIXME: rename "files" to "values" or something
        self.backend.propset(objectid, property, files=files, o_excl=o_excl)

    def validate(self):
        return self.backend.validate()


def parse_pstorerc():
    '''
    Read ~/.pstorerc for default arguments.

    "There was a facility that would execute a bunch of commands stored
    in a file; it was called runcom for "run commands", and the file
    began to be called "a runcom". rc in Unix is a fossil from that
    usage."
    '''
    # TODO: emit warning if .pstorerc is found but not readable
    rc_args, file = [], None
    try:
        file = open(os.environ['HOME'] + '/.pstorerc', 'r')
        rc_args.extend(file.read().split())
    except Exception:
        pass
    finally:
        if file:
            file.close()
    return rc_args


def parse_options(args):
    '''
    Parse command line options, with default options read from the
    .pstorerc file prefixed. This way you can set defaults there, like
    the --store-url, but it can be overridden manually.
    '''
    rc_args = parse_pstorerc()

    # Quick hack to warn people of duplicate store-urls.
    has_default_store_url = any(i.startswith('--store-url') for i in rc_args)
    has_new_store_url = any(i.startswith('--store-url') for i in args[1:])
    if has_default_store_url and has_new_store_url:
        sys.stderr.write(  # FIXME?
            'WARNING: setting --store-url does not override .pstorerc\n')

    try:
        optlist, args = gnu_getopt(
            [args[0]] + rc_args + args[1:],  # inject defaults
            'hVcPp:' + 'ak:l:s:u:v',  # command options + configuration options
            ('help', 'version', 'create', 'chpass', 'lookup-machine',
             'propedit', 'consistency-check')
            + ('all', 'search=', 'store-url=', 'user=', 'verbose')
        )
    except GetoptError as e:
        raise UserError(str(e))

    config = {
        'show_all': False,
        'store_urls': [],
        'user': getuser(),
        'verbose': False
    }

    command = None
    for option, arg in optlist:
        # Command options
        if option in ('--help', '-h'):
            command = 'help'  # always allow -h
        elif option in ('--version', '-V'):
            if command != 'help':
                command = 'version'  # override all but -h
        elif option in ('--create', '-c',
                        '--change-password', '-P',
                        '--propedit', '-p',
                        '--search', '-s',
                        '--lookup-machine',
                        '--consistency-check'):
            if not command:
                if option in ('--create', '-c'):
                    command = 'create'
                elif option in ('--change-password', '-P'):
                    command = 'chpass'
                elif option in ('--lookup-machine',):
                    command = 'list_minimal'
                elif option in ('--propedit', '-p'):
                    if arg == 'l':
                        command = 'proplist'
                    elif arg == 'g':
                        command = 'propget'
                    elif arg == 's':
                        command = 'propset'
                    elif arg == 'e':
                        command = 'propsetenc'
                    else:
                        raise UserError('Propedit option takes g, s, e or l')
                elif option in ('--search', '-s'):
                    command = 'search'
                    config['search'] = arg  # see below for format
                elif option in ('--consistency-check',):
                    command = 'check_consistency'
                else:
                    raise UserError('Unknown command; programming error')
            elif command != 'help':
                command = 'multiple_commands'

        # Configuration options
        elif option in ('--all', '-a'):
            config['show_all'] = True
        elif option in ('--store-url',):
            while len(arg) and arg[-1] == '/':  # strip trailing slashes
                arg = arg[0:-1]
            if (not arg.startswith('http://')
                    and not arg.startswith('https://')):
                raise UserError('bad store-url; we only do http(s)', arg)
            config['store_urls'].append(arg)
        elif option in ('--user', '-u'):
            config['user'] = arg
        elif option in ('--verbose', '-v'):
            config['verbose'] = True

        # Evil hacks to allow the password input into ssh directly
        elif option in ('-l',):
            # XXX: move this to the ssh_host_hack bit..? or rename ssh_host to
            # ssh_arg or something..
            # Assume args[1] is the machine name here
            machine_name = args[1]
            # "x" (or "-") => use machine_name
            if arg in ('-', 'x') and len(args) > 1:
                config['ssh_host'] = machine_name
            # "username" => use username@machine_name
            elif '.' not in arg:
                config['ssh_host'] = arg + '@' + machine_name
            # "host-part." => use host-part.machine-domain"
            elif arg.endswith('.'):
                config['ssh_host'] = arg + machine_name.split('.', 1)[-1]
            # "whatever-else" => use "whatever-else"
            else:
                config['ssh_host'] = arg
            del machine_name
            print('Attempting ssh login with arg: {0}'.format(
                config['ssh_host']))
            print('(if you see "Host key verification failed", '
                  'you need to ssh manually)')

        else:
            raise NotImplementedError('Unhandled option', option)

    if command == 'multiple_commands':
        raise UserError('multiple command options encountered, see -h')

    return command, args[1:], config  # drop argv0


def parse_allow_revoke(args):
    '''
    Expects a list of usernames with + or - prefix. Split these
    usernames into two lists and return. Note that everything is in
    lower case.
    '''
    allow, revoke = [], []
    for arg in args:
        if len(arg) < 2 or arg[0] not in ('+', '^'):
            sys.stderr.write(
                'WARNING: skipping unparseable allow/revoke '
                'statement %s\n' % (arg,))
        elif arg[0] == '+':
            allow.append(arg[1:].lower())
        elif arg[0] == '^':
            revoke.append(arg[1:].lower())
        else:
            assert False, 'Programming error'
    return allow, revoke


def run_command(command, args, config):
    if config['verbose']:
        sys.stderr.write('- Executing "%s" on stores %r as user "%s"\n' % (
            command, config['store_urls'], config['user']))

    if command in ('check_consistency', 'search'):
        pass
    elif args:
        name = args.pop(0).lower()
    elif command == 'default':
        name = ''  # lookup all
    else:
        raise UserError('need machine name')

    if command in ('check_consistency', 'proplist', 'search'):
        if len(args):
            raise UserError('unexpected argument')
    elif command in ('propget', 'propset', 'propsetenc'):
        if len(args) != 1:
            raise UserError('invalid number of arguments')
        property = args.pop(0).lower()
    else:
        allow, revoke = parse_allow_revoke(args)

    if command == 'default':
        if not allow and not revoke:
            command = 'show_or_list'
        else:
            command = 'allow_and_revoke'

    if command in ('create', 'chpass'):
        if command == 'create' and revoke:
            raise UserError('cannot revoke users when adding a new machine')

        if 'PSTORE_NOINPUT' in os.environ:
            # For tests we'd like to create passwords automatically.
            new_password = 'example-password'
        else:
            new_password = getpass('Type new machine password: ')
            new_password2 = getpass('Type new machine password again: ')
            if new_password != new_password2:
                raise UserError('passwords do not match')
            del new_password2

        try:
            # If py3, then this is a unistr, and there is no decode.
            new_password.decode
        except AttributeError:
            new_password = new_password.encode('utf-8')

    pstore = PStoreInterface(config)

    if command == 'create':
        pstore.add_machine(name, new_password, [config['user']] + allow)

    elif command == 'chpass':
        pstore.change_password(name, new_password)
        if allow or revoke:
            pstore.change_permissions(name, allow, revoke)

    elif command == 'allow_and_revoke':
        if not allow and not revoke:
            raise UserError('need something to allow/revoke')
        pstore.change_permissions(name, allow, revoke)

    elif command == 'list_minimal':
        # Do not ask for passwords when called from a bash_completion script.
        PStoreCrypt.get().askpass = PStoreCrypt.ASKPASS_NEVER
        allowed_only = (not config['show_all'])
        objects = pstore.get_objects(
            objectid_contains=name, allowed_only=allowed_only,
            verbose=False)
        silenced_sigpipe(print_results_property_keys, objects)

    elif command == 'propget':
        # TODO: Add the possibility to replace stdout with a file..
        fp = pstore.propget(name, property)
        # Use a sendfile(2) compatible call to push everything from the fp to
        # stdout.
        silenced_sigpipe(sendfile, bytes_stdout, fp)
        # We dropped the last line feed on input from a TTY. So, if the output
        # is a tty too, we'll add the LF again.
        if sys.stdout.isatty():
            sys.stdout.write('\n')

    elif command == 'proplist':
        allowed_only = (not config['show_all'])
        properties = pstore.get_properties(
            name, allowed_only=allowed_only)

        silenced_sigpipe(print_result_properties, properties, config)

    elif command in ('propset', 'propsetenc'):
        # TODO: Add the possibility to replace stdin with a file..
        fp = bytes_stdin
        # Warn when storing unencrypted properties.
        if command == 'propset':
            if 'PSTORE_NOINPUT' not in os.environ:
                sys.stderr.write('NOTICE: not encrypting the value\n')
        # Set allowed users automatically.
        allowed_users = (None, True)[command == 'propsetenc']
        pstore.propset(name, property, fp, allowed_users=allowed_users)

    elif command == 'show_or_list':
        # Try show first. If that fails, do a listing.
        found_machine = False

        if name:
            try:
                machine_password, machine_info = pstore.get_password(name)
            except (NotAllowed, NotFound):
                # A superadmin gets a 404 on no-such-object. A mere mortal gets
                # a 403 instead. Catch both.
                pass
            else:
                run_show_password(machine_info, machine_password,
                                  ssh_host_hack=config.get('ssh_host', None))
                found_machine = True

        # If there was no name, or the name wasn't a machine, do a listing.
        if not found_machine:
            limited = not config['show_all']
            machines = pstore.get_objects(objectid_contains=name,
                                          allowed_only=limited, verbose=True)
            if not machines:
                raise UserError('no visible machines match %s' % (name,))
            silenced_sigpipe(print_results_list, machines)

    elif command == 'search':
        # Search uses KEY=VALUE search where KEY and VALUE are substring
        # matched. In the future we may want to open the possibility to
        # use regex, in that case we could accept certain prefixes,
        # like: ~ = regex, ^ = startswith
        # But we'd have to take care when splitting the KEY from the
        # VALUE. (Possibly by simply accepting at most one equals
        # sign, which we do right now.)
        #
        # Current format:
        #   [KEY=]VALUE
        # NOTE: This was KEY[=VALUE] up until (including) pstore 1.1.3.
        #
        search_parts = config['search'].split('=')
        if len(search_parts) == 1:
            search_parts.insert(0, None)  # insert "empty" key
        elif len(search_parts) != 2:
            raise UserError(
                'search string can contain at most one equals sign')

        if any(part and part[0] not in ALNUM for part in search_parts):
            raise UserError(
                'search format must not start with non-alnum character; '
                'for forward compatibility')
        if all(not part for part in search_parts):
            raise UserError('refusing to search for the empty string')

        search_kwargs = {}
        if search_parts[0]:
            search_kwargs['propkey_icontains'] = search_parts[0]
        if search_parts[1]:
            # If set, we'll search unencrypted properties only.
            search_kwargs['propvalue_icontains'] = search_parts[1]
        limited = not config['show_all']

        properties = pstore.search_properties(
            allowed_only=limited, **search_kwargs)
        if not properties:
            raise UserError('no search results')

        silenced_sigpipe(print_result_search, properties, config)

    elif command == 'check_consistency':
        errors = pstore.validate()
        if not errors:
            if config['verbose']:
                print('Database is consistent.')
        else:
            for error in errors:
                print('There is a problem with %s %s' % tuple(error[0:2]))
                print('  problem: {0}'.format(error[2]))
                print('  solution: {0}'.format(error[3]))
                print('')
            raise UserError('database is inconsistent')

    else:
        raise NotImplementedError('Unknown command', command)


def run_show_password(machine_info, machine_password, ssh_host_hack=None):
    # FIXME FIXME FIXME
    # machine_password should be in some kind of mutable XORed form,
    # so it doesn't easily show up in memory dumps
    # note that the memory is already exposed earlier on.. go back and fix
    # it there too.
    # FIXME FIXME FIXME

    # Er.. why do we assume that the user wants all this on his screen?
    silenced_sigpipe(print_result_related_properties, machine_info)

    if ssh_host_hack:
        # Run ssh
        run_ssh_host_hack(ssh_host_hack)
    else:
        # Show password
        silenced_sigpipe(print_result_password, machine_password)


def run_ssh_host_hack(machine_password, ssh_host_hack):
    if 'DISPLAY' not in os.environ:
        os.environ['DISPLAY'] = 'whatever:0'
    os.environ['LD_PRELOAD'] = SSH_ASKPASS_PRELOAD
    os.environ['SSH_ASKPASS'] = SSH_ASKPASS_APP
    os.environ['SSH_PASSWORD'] = mktemp()
    # Not really secure.. using the filesystem.. but it'll have
    # to do for now..
    temp = open(os.environ['SSH_PASSWORD'], 'w')
    try:
        temp.write(machine_password)
    finally:
        temp.close()
        del temp
    try:
        os.execve('/usr/bin/ssh',
                  ['ssh', '-oPubkeyAuthentication=no', ssh_host_hack],
                  os.environ)
    finally:
        # We don't usually get here, but if we do, make sure we clean up
        # the password.
        temp = open(os.environ['SSH_PASSWORD'], 'w')
        temp.write('X' * 1024)
        temp.close()
        os.unlink(os.environ['SSH_PASSWORD'])


def silenced_sigpipe(callable, *args, **kwargs):
    try:
        ret = callable(*args, **kwargs)
    except IOError as e:
        if e.errno != errno.EPIPE:
            raise
        sys.exit(0)  # or 141 = 128 + 13(SIGPIPE) ?
    return ret


def print_help(**kwargs):
    print(r'''%(title)s
                                                --------------
Usage:                                          | *        * |
  pstore machine                                |   \_  _/   | Python
    (look up a machine password)                |  ___\/___  | Protected
  pstore machine +user1 ^user2                  |    _/\_    | Password
    (allow (+) and revoke (^) access)           |   /    \   | Store
  pstore -c machine [+user1]                    | *        * |
    (add machine and allow access)              --------------
  pstore -P machine [+user1] [^user2]
    (change machine password and allow/revoke access)
  echo Under the cupboard | pstore -ps machine location
    (add unencrypted location property to machine; use -pl to list, -pg
     to get and -pe to store *encrypted* properties)
  pstore -s [propkey=][propvalue]
    (search for properties, only public property values can be searched,
     using substring matching, case sensitivity depends on backend)

Command options:
%(commands)s
Configuration options:
%(configs)s%(extra)s''' % kwargs)


def print_results_list(machines):
    fmt = '%1s %-25s %s'
    print(fmt % (' ', 'Machine', 'User access'))
    print('-' * 72)
    for machine in sorted(machines.keys()):
        properties = machines[machine]
        print(fmt % (
            '+', machine,
            ', '.join(sorted(properties['users'].keys()))))


def print_result_password(machine_password):
    if hasattr(os, 'isatty') and os.isatty(sys.stdout.fileno()):
        # ansi color the password so it's less visible
        # TODO: invert this if the console is not white-on-black
        machine_password = b'\x1b[7;30m%s\x1b[0m' % (machine_password,)
    bytes_stdout.write(b'password = %s\n' % (machine_password,))


def print_result_properties(properties, config):
    if config['verbose']:
        for property in sorted(properties.keys()):
            value = properties[property]
            info = 'size=%d' % (value['size'],)
            if value['enctype'] == 'none':
                info += ', unencrypted'
            print('%s (%s)' % (property, info))
    else:
        for property in sorted(properties.keys()):
            print(property)


def print_results_property_keys(properties):
    for objectid in sorted(properties.keys()):
        print(objectid)


def print_result_related_properties(machine_info):
    for property in sorted(machine_info['properties'].keys()):
        if property == PStoreInterface.PASSWORD_PROPERTY:
            continue  # do that one last..
        info = machine_info['properties'][property]
        if info['enctype'] == 'none':
            if info['data'] is not None:
                data = info['data'].decrypt_with().read()
                if b'\n' in data:
                    bytes_stdout.write(b'%s = \\\n | %s\n' % (
                        property.encode('ascii'),
                        data.replace(b'\n', b'\n | '),))
                else:
                    bytes_stdout.write(b'%s = %s\n' % (
                        property.encode('ascii'),
                        data))
            else:
                print('%s = (%s byte document)' % (property, info['size']))
        else:
            print('%s = (%s byte encrypted)' % (property, info['size']))


def print_result_search(properties, config):
    fmt = '%1s %-25s %s'
    print(fmt % (' ', 'Machine', 'Property and value'))
    print('-' * 72)
    for machine in sorted(properties.keys()):
        props = properties[machine]['properties']
        for i, propname in enumerate(sorted(props.keys())):
            if i == 0:
                fmt_args = ['+', machine, propname, '=']
            else:
                fmt_args = ['', '', propname, '=']
            info = props[propname]
            if 'data' in info:
                assert info['enctype'] == 'none'
                data = info['data'].decrypt_with().read()
                if len(data) < 80:
                    fmt_args.append(data.decode('utf-8', 'ascii'))
                else:
                    fmt_args.append('(%d byte document)' % info['size'])
            elif info['enctype'] != 'none':
                fmt_args.append('(%d byte encrypted)' % info['size'])
            else:
                fmt_args.append('(%d byte document)' % info['size'])
            fmt_args[2:] = [' '.join(fmt_args[2:])]

            print(fmt % tuple(fmt_args))


def run_usage(verbose=False):
    # Check if we can use the evil ssh auto-login.
    evil_ssh_hacks = os.path.exists(SSH_ASKPASS_PRELOAD)

    # Select verbosity.
    if verbose and evil_ssh_hacks:
        matcher = (lambda i: i in (0, 1, 2))
    elif verbose:
        matcher = (lambda i: i in (0, 1))
    else:
        matcher = (lambda i: i in (0,))

    # The command options.
    commands = (
        ('  --create, -c          ', 0,
         'Add new machine (instead of looking up one)'),
        ('  --chpass, -P          ', 0,
         'Change machine password'),
        ('  --help, -h            ', 0,
         'Show help and exit (use -v for verbose help)'),
        ('  --lookup-machine      ', 1,
         'Look up machine names only (*L)'),
        ('  --propedit=A, -p A    ', 1,
         'Act on properties; list/get/set/encrypt (*P)'),
        ('  -l [x|SSH_ARG]        ', 2,
         'Evil hack to ssh(1) to machine directly (*S)'),
        ('  --consistency-check   ', 1,
         'Check database consistency (*C)'),
    )

    # The configuration options.
    configs = (
        ('  --all, -a             ', 0,
         'Privileged users use this to show more machines'),
        ('  --user=USER, -u       ', 0,
         'Your pstore username (defaults to $USER)'),
        ('  --store-url=URL       ', 0,
         'Backend URL (supply more as fallbacks)'),
        ('  --verbose, -v         ', 0,
         'Verbose mode (use --help -v for more help)'),
        ('  --version, -V         ', 1,
         'Print version'),
    )

    # Undocumented environment variables:
    #  * PSTORE_NOINPUT
    #    If nonempty, will remove all password/value prompts. Used by the
    #    automated tests.

    # Extra stuff.
    extra = ''
    if matcher(1):
        extra += ('\n(*C) Consistency checks should be run periodically '
                  'by the admin.'
                  '\n(*L) For bash completion. Will never ask for a password.'
                  '\n(*P) Use one of -pl, -pg, -ps, -pe, where -pe is the '
                  'encrypted -ps.')
    if matcher(2):
        extra += ('\n(*S) SSH_ARG can be one of "username", '
                  '"[username@]replace-host.",\n'
                  '    "[username@]entire-host.name". '
                  'Requires ssh_askpass.so.')
    if extra:
        extra = '\n' + extra

    # Combine the data.
    commands = '\n'.join(i[0] + i[2] for i in commands if matcher(i[1]))
    configs = '\n'.join(i[0] + i[2] for i in configs if matcher(i[1]))

    # Print the help.
    silenced_sigpipe(
        print_help, title='pstore %s CLI' % (VERSION_STRING,),
        commands=commands, configs=configs, extra=extra)


def run_version():
    print('pstore %s CLI' % (VERSION_STRING,))


def pstore(args):
    command, args, config = parse_options(args)

    if command == 'help':
        run_usage(config['verbose'])
        sys.exit(0)
    elif command == 'version':
        run_version()
        sys.exit(0)

    if not config['store_urls']:
        raise UserError('need at least one store-url to function')

    # If you set the PSTORE_NOINPUT environment variable, we won't ask for
    # passwords, but return username + '2' as password instead. This allows
    # automated tests to run.
    if bool('PSTORE_NOINPUT' in os.environ):
        askpass = PStoreCrypt.ASKPASS_USERNAME2     # automated tests
    else:
        askpass = PStoreCrypt.ASKPASS_DEFAULT       # default

    # Not so nice.. but we have to do this somewhere..
    PStoreCrypt.create(askpass=askpass)

    run_command(command or 'default', args, config)


def main():
    try:
        pstore(sys.argv)
    except KeyboardInterrupt:
        sys.exit(130)  # 128+SIGINT
    except PStoreException as e:
        # TODO: get __cause__ in verbose mode?
        sys.stderr.write(': '.join(str(i) for i in e.args) + '\n')
        sys.exit(1)


if __name__ == '__main__':
    main()

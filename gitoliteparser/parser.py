import re
import os
import os.path
import glob
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

# regular-expressions copied from gitolite source
# https://github.com/sitaramc/gitolite/blob/master/src/lib/Gitolite/Conf.pm
_re_part_name = "[\w@\-_]+"
_re_group = re.compile('^(@\S+)\s*=\s*(\w*)')
_re_repo = re.compile('repo\s+([\w\-_]*)')
_re_perm = re.compile('^(-|C|R|RW\+?(?:C?D?|D?C?)M?)\s*(\w+)?\s*=\s*('+_re_part_name+')')

class ParseError(Exception):
    line = None
    message = None

    def __init__(self, message, line):
        self.message = message
        self.line = line

    def __str__(self):
        return "{0}('{1}', {2})".format(self.__class__.__name__, self.message, self.line)


class Permission(object):
    user = None
    perm = None
    path = None

    def __init__(self):
        self.perm = 'RW'

    def id(self):
        raise NotImplementedError()

    def __eq__(self, other):
        return self.user == other.user and self.path == other.path and self.perm == other.perm

    def serialize(self):
        if self.path:
            return "    {0} {1} = {2}".format(self.perm, self.path, self.user.id())
        return "    {0} = {1}".format(self.perm, self.user.id())


class User(object):
    name = None

    def __init__(self, name):
        self.name = name.strip()

    def __eq__(self, other):
        return self.name == other.name

    def id(self):
        return self.name

    def serialize(self):
        return self.name

class Repository(object):
    name = None
    permissions = set()

    def __init__(self, name):
        self.name = name.strip()
        self.clear_permissions()

    def clear_permissions(self):
        self.permissions = set()

    def add_permission(self, perm):
        self.permissions.add(perm)

    def id(self):
        raise NotImplementedError()

    def serialize(self):
        return "repo {0}\n{1}\n".format(self.name, '\n'.join(permission.serialize() for permission in self.permissions))


class Group(object):
    name = None
    members = set()

    def __init__(self, name):
        self.name = name.strip().lstrip('@')
        self.members = set()

    def __eq__(self, other):
        return self.name == other.name and self.members == other.members

    def id(self):
        return "@{0}".format(self.name)

    def serialize(self):
        return "@{0} = {1}".format(self.name, ' '.join(member.id() for member in self.members))


class Configfile(object):
    groups = None
    repos = None

    def __init__(self):
        self.groups = OrderedDict()
        self.repos = OrderedDict()

    def serialize(self):
        return '{0}\n\n{1}'.format( \
                '\n'.join(repo.serialize() for repo in self.repos.itervalues()), \
                '\n'.join(group.serialize() for group in self.groups.itervalues()))

    def set_group(self, group):
        self.groups[group.name] = group

    def set_repo(self, repo):
        self.repos[repo.name] = repo

    def has_repo(self, reponame):
        return self.repos.has_key(reponame)

    def remove_repo(self, reponame):
        try:
            self.repos.pop(reponame)
        except KeyError:
            pass

    def repo_names(self):
        return self.repos.keys()

    def parse(self, filename):
        line_counter = 0
        current_repo = None

        for line in open(filename).readlines():
            line = line.strip()
            line_counter += 1

            if line == '':
                continue

            mo = _re_perm.match(line)
            if mo: # permission
                if not current_repo:
                    raise ParseError("Found permission line outside of repository definition", line_counter)
                perm = Permission()
                perm.perm = mo.group(1)
                perm.path = mo.group(2)

                if mo.group(3).startswith('@'):
                    perm.user = Group(mo.group(3))
                else:
                    perm.user = User(mo.group(3))
                current_repo.permissions.add(perm)
                continue

            if current_repo is not None:
                self.set_repo(current_repo)
                current_repo = None

            mo = _re_group.match(line)
            if mo: # group definitions
                group = Group(mo.group(1))
                for username in mo.group(2).split(' '):
                    group.members.add(User(username))
                self.set_group(group)
                continue

            mo = _re_repo.match(line)
            if mo: # repository start
                current_repo = Repository(mo.group(1))
                continue

            raise ParseError('unknown directive', line_counter)


class AdminRepository(Configfile):
    def __init__(self, path,  keydir_name='keys'):
        Configfile.__init__(self)

        self._repo_path = path
        self._key_path = os.path.join(path, keydir_name)
        if not os.path.isdir(self._key_path):
            os.mkdir(self._key_path)

        conf_dir = os.path.join(path, "conf")
        if not os.path.isdir(conf_dir):
            os.mkdir(conf_dir)
        self._user_repo_config = os.path.join(conf_dir, "gitolite.conf")

        if os.path.isfile(self._user_repo_config):
            self.parse(self._user_repo_config)

    def getSSHKeys(self):
        keys = glob.glob(os.path.join(self._key_path, '*.pub'))
        key_data = {}
        for keyfile in keys:
            keyname = os.path.basename(keyfile)
            username = keyname[:-4]
            key_data[username] = keyname
        return key_data

    def __get_ssh_key_name(self, username):
        return username + ".pub"

    def __get_ssh_key_path(self, username):
        return os.path.join(self._key_path, self.__get_ssh_key_name(username))

    def addSSHKey(self, username, sshkey):
        key_file_name = self.__get_ssh_key_path(username)
        with open(key_file_name, 'w') as new_key_file:
            new_key_file.write(sshkey)

    def rmSSHKey(self, username):
        key_file_name = self.__get_ssh_key_path(username)
        try:
            os.remove(key_file_name)
        except OSError:
            pass
        return True

    def cleanup(self):
        # sort out unused keys
        usernames = set()
        for repo in self.repos.itervalues():
            for perm in repo.permissions:
                if type(perm.user) == User:
                    usernames.add(perm.user.name)
        for group in self.groups.itervalues():
            for user in group.members:
                if type(user) == User:
                    usernames.add(user.name)
        for user in self.getSSHKeys().iterkeys():
            if not user in usernames:
                self.rmSSHKey(user)

    def save(self):
        self.cleanup()
        with open(self._user_repo_config, 'w') as fh:
            fh.write(self.serialize())

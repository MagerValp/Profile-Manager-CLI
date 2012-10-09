#!/usr/bin/python


import os
import sys
import optparse
import urllib
import urllib2
import cookielib
import json
import hashlib
import csv
import codecs
import cStringIO
import getpass
from Foundation import CFPreferencesCopyAppValue


BUNDLE_ID = "se.gu.it.pmcli"


# Classes to deal with the csv module's inability to deal with Unicode, from
# http://docs.python.org/library/csv.html#examples

class UTF8Recoder:
    """
    Iterator that reads an encoded stream and reencodes the input to UTF-8
    """
    def __init__(self, f, encoding):
        self.reader = codecs.getreader(encoding)(f)
    
    def __iter__(self):
        return self
    
    def next(self):
        return self.reader.next().encode("utf-8")

class UnicodeCSVReader:
    """
    A CSV reader which will iterate over lines in the CSV file "f",
    which is encoded in the given encoding.
    """
    
    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        f = UTF8Recoder(f, encoding)
        self.reader = csv.reader(f, dialect=dialect, **kwds)
    
    def next(self):
        row = self.reader.next()
        return [unicode(s, "utf-8") for s in row]
    
    def __iter__(self):
        return self

class UnicodeCSVWriter:
    """
    A CSV writer which will write rows to CSV file "f",
    which is encoded in the given encoding.
    """
    
    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        self.queue = cStringIO.StringIO()
        self.writer = csv.writer(self.queue, dialect=dialect, **kwds)
        self.stream = f
        self.encoder = codecs.getincrementalencoder(encoding)()
    
    def writerow(self, row):
        self.writer.writerow([s.encode("utf-8") for s in row])
        data = self.queue.getvalue()
        data = data.decode("utf-8")
        data = self.encoder.encode(data)
        self.stream.write(data)
        self.queue.truncate(0)
    
    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


class PMError(BaseException):
    pass

class ProfileManager(object):
    
    def __init__(self, server, scheme="https"):
        super(ProfileManager, self).__init__()
        self.server = server
        self.scheme = scheme
        self.headers = dict()
        self.cookiejar = cookielib.CookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookiejar))
        #self.groups_by_id = None
        self.groups_by_name = None
    
    def create_request(self, path, data=None):
        return urllib2.Request("%s://%s%s" % (self.scheme, self.server, path), data, self.headers)
    
    def open(self, path, data=None):
        return self.opener.open(self.create_request(path, data))
    
    def open_or_die(self, path, data=None):
        r = self.opener.open(self.create_request(path, data))
        if r.getcode() != 200:
            raise PMError("Server error: %d" % r.getcode())
        return r
    
    def authenticate(self, username, password):
        try:
            self.username = username
            self.password = password
            # Load login form and get cookie.
            r = self.open_or_die("/auth")
            # Request CSRF token.
            r = self.open_or_die("/auth/csrf")
            csrf_token = r.read().rstrip()
            # Add token to request headers.
            self.headers["X-CSRF-Token"] = csrf_token
            # Request auth challenge.
            r = self.open_or_die("/auth/challenge_advanced", "username=%s\n" % username)
            # Digest nonce="ivnOFZibtwTI5F9/qQhedEkjsBYjSKnxMnTaxrxrCMp4MmR8",realm="GU",qop="auth",algorithm=md5-sess
            challenge_data = r.read().rstrip()
            if not challenge_data.startswith("Digest "):
                raise PMError("Unrecognized auth challenge")
            challenge = dict()
            for item in challenge_data[7:].split(","):
                k, _, v = item.partition("=")
                if v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                challenge[k] = v
            # Authenticate with digest.
            ncvalue = "%08x" % 1
            method = "AUTHENTICATE"
            uri = "/"
            cnonce = os.urandom(8).encode("hex")
            realm = challenge["realm"]
            nonce = challenge["nonce"]
            qop = challenge["qop"]
            algorithm = challenge["algorithm"]
            if algorithm.lower() != "md5-sess":
                raise PMError("Unsupported auth algorithm %s" % repr(algorithm))
            md5 = lambda x: hashlib.md5(x).digest()
            md5_hex = lambda x: hashlib.md5(x).hexdigest()
            ha1 = md5_hex("%s:%s:%s" % (md5("%s:%s:%s" % (username, realm, password)), nonce, cnonce))
            ha2 = md5_hex("%s:%s" % (method, uri))
            response = md5_hex(":".join((ha1, nonce, ncvalue, cnonce, qop, ha2)))
            digest_dict = {
                "username": username,
                "realm": realm,
                "nonce": nonce,
                "uri": uri,
                "qop": qop,
                "nc": ncvalue,
                "cnonce": cnonce,
                "algorithm": algorithm,
                "response": response,
            }
            data = "Digest " + ",".join('%s="%s"' % (k, v) for k, v in digest_dict.items())
            r = self.open_or_die("/auth/digest_login", data)
            # {"auth_token":"D9D47C7D-F3E3-4214-8416-9B4DBB09F530","success":true}
            result = json.loads(r.read())
            if not result["success"]:
                raise PMError("Authentication failed")
            self.auth_token = result["auth_token"]
            # Send auth_token to authentication callback.
            r = self.open_or_die("/devicemanagement/api/authentication/callback?auth_token=%s" % self.auth_token)
        except urllib2.URLError as e:
            raise PMError(e.reason)
    
    def do_magic(self, magic):
        r = self.open_or_die("/devicemanagement/api/magic/do_magic?auth_token=%s" % self.auth_token, json.dumps(magic))
        return json.loads(r.read())
    
    def add_placeholder_device(self, name, serial=None, imei=None, meid=None, udid=None):
        args = dict()
        args["DeviceName"] = name
        if serial is not None:
            args["SerialNumber"] = serial
        if imei is not None:
            args["IMEI"] = imei
        if meid is not None:
            args["MEID"] = meid
        if udid is not None:
            args["udid"] = udid
        response = self.do_magic({"device":
            {"create":
                [[args]]
            }
        })
        try:
            device_id = response["result"]["device"]["created"][0]["id"]
        except:
            raise PMError("Couldn't add device")
        return device_id
    
    def delete_device(self, device_id):
        response = self.do_magic({"device":{"destroy":[[device_id]]}})
        import pprint
        pprint.pprint(response)
    
    def add_device_to_group(self, group_name, device_id):
        group_id = self.get_group(group_name)["id"]
        response = self.do_magic({
            "device_group": {
                "add_device": [[group_id, {"id": [device_id]}]]
            }
        })
    
    def get_device_ids(self):
        response = self.do_magic({"device": {"find_all": [["GIMME"]]}})
        return response["remote"]["GIMME"][0][1:]
    
    def get_device_details(self, device_ids):
        return self.do_magic({
            "device": {
                "get_details": [[None, {"ids": device_ids}]]
            }
        })["result"]["device"]["retrieved"]
    
    def get_device_group_ids(self):
        response = self.do_magic({"device_group": {"find_all": [["GIMME"]]}})
        return response["remote"]["GIMME"][0][1:]
    
    def get_device_group_details(self, group_ids):
        return self.do_magic({
            "device_group": {
                "get_details": [[None, {"ids": group_ids}]]
            }
        })["result"]["device_group"]["retrieved"]
    
    def load_groups(self):
        if self.groups_by_name is None:
            #self.groups_by_id = dict()
            self.groups_by_name = dict()
            for group in self.get_device_group_details(self.get_device_group_ids()):
                #self.groups_by_id[group_id] = group
                self.groups_by_name[group["name"]] = group
    
    def get_group(self, name):
        self.load_groups()
        try:
            return self.groups_by_name[name]
        except KeyError:
            raise PMError("No such group %s" % repr(name))
    

def do_test(pm, args):
    device_id = pm.add_placeholder_device("pmcli_test", serial="C080dea31")
    pm.add_device_to_group("slask", device_id)


def do_add_placeholder(pm, args):
    usage = "Usage: add_placeholder name (serial|imei|meid|udid)=value [group]"
    if len(args) not in (2, 3):
        sys.exit(usage)
    name = args[0]
    id_type, equal, ident = args[1].partition("=")
    if equal != "=":
        sys.exit(usage)
    if id_type not in ("serial", "imei", "meid", "udid"):
        sys.exit(usage)
    try:
        group = args[2]
    except IndexError:
        group = None
    device_id = pm.add_placeholder_device(name, **{id_type: ident})
    if group:
        pm.add_device_to_group(group, device_id)
    

def unicode_csv_reader(unicode_csv_data, dialect=csv.excel, encoding="utf-8", **kwargs):
    # csv.py doesn't do Unicode; encode temporarily as UTF-8:
    csv_reader = csv.reader(unicode_csv_data, dialect=dialect, **kwargs)
    for row in csv_reader:
        # decode UTF-8 back to Unicode, cell by cell:
        yield [cell.decode(encoding) for cell in row]
    

def do_import_placeholders(pm, args):
    if len(args) != 1:
        sys.exit("Usage: import_placeholders input.csv")
    rows = list(UnicodeCSVReader(open(args[0])))
    if len(rows) < 2:
        sys.exit("Bad csv file")
    headers = rows[0]
    if headers != [u"name", u"ids", u"groups"]:
        sys.exit("Missing required column headers")
    for row in rows[1:]:
        # Empty names are displayed as "New Device" in PM.
        name = row[0] or None
        ids = dict()
        for t, _, i in [x.partition("=") for x in row[1].split("+")]:
            ids[t] = i
        device_id = pm.add_placeholder_device(name, **ids)
        if row[2]:
            for group in row[2].split("+"):
                pm.add_device_to_group(group, device_id)
    

def do_dump_devices(pm, args):
    if len(args) != 1:
        sys.exit("Usage: dump_devices output.json")
    output_fname = args[0]
    device_ids = pm.get_device_ids()
    devices = pm.get_device_details(device_ids)
    with open(output_fname, "w") as f:
        json.dump({"Devices": devices}, f, indent=4)
    

def do_export_placeholders(pm, args):
    if len(args) != 1:
        sys.exit("Usage: export_placeholders output.csv")
    output_fname = args[0]
    with open(output_fname, "w") as f:
        writer = UnicodeCSVWriter(f)
        writer.writerow(["name", "ids", "groups"])
        device_ids = pm.get_device_ids()
        for device in pm.get_device_details(device_ids):
            # Handle devices with empty names.
            name = device["DeviceName"] or ""
            ids = list()
            for k, v in (("SerialNumber", "serial"),
                         ("IMEI", "imei"),
                         ("MEID", "meid"),
                         ("udid", "udid"),
                        ):
                if device[k]:
                    ids.append("%s=%s" % (v, device[k]))
            idstr = "+".join(ids)
            groups = list()
            if device["device_groups"]:
                for group in pm.get_device_group_details(device["device_groups"]):
                    if group:
                        groups.append(group["name"])
            groupstr = "+".join(groups)
            writer.writerow([name, idstr, groupstr])
    

def main(argv):
    p = optparse.OptionParser()
    p.set_usage("""Usage: %prog [options] verb""")
    p.add_option("-s", "--server")
    p.add_option("-u", "--username")
    p.add_option("-p", "--password")
    p.add_option("-P", "--prompt-password", action="store_true")
    options, argv = p.parse_args(argv)
    if len(argv) < 2:
        print >>sys.stderr, p.get_usage()
        return 1
    
    verbs = dict()
    for name, func in globals().items():
        if name.startswith("do_"):
            verbs[name[3:]] = func
    
    action = argv[1]
    if action not in verbs:
        sys.exit("Unknown verb %s" % action)
    
    server = options.server or CFPreferencesCopyAppValue("server", BUNDLE_ID)
    if not server:
        sys.exit("No server specified")
    username = options.username or CFPreferencesCopyAppValue("username", BUNDLE_ID)
    if not username:
        sys.exit("No username specified")
    password = options.password or CFPreferencesCopyAppValue("password", BUNDLE_ID)
    if options.prompt_password or not password:
        password = getpass.getpass("Password for %s@%s: " % (username, server))
    if not password:
        sys.exit("No password specified")
    
    pm = ProfileManager(server)
    try:
        pm.authenticate(username, password)
    except PMError as e:
        sys.exit(e)
    
    try:
        verbs[action](pm, list(x.decode("utf-8") for x in argv[2:]))
    except PMError as e:
        sys.exit(e)
    
    return 0
    

if __name__ == '__main__':
    sys.exit(main(sys.argv))
    

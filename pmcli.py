#!/usr/bin/python


import os
import sys
import optparse
import urllib
import urllib2
import cookielib
import json
import hashlib

import itertools
import mimetools
import mimetypes

# http://www.doughellmann.com/PyMOTW/urllib2/#uploading-files
class MultiPartForm(object):
    """Accumulate the data to be used when posting a form."""
    
    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = mimetools.choose_boundary()
        return
    
    def get_content_type(self):
        return 'multipart/form-data; boundary=%s' % self.boundary
    
    def add_field(self, name, value):
        """Add a simple field to the form data."""
        self.form_fields.append((name, value))
        return
    
    def add_file(self, fieldname, filename, body, mimetype=None):
        """Add a file to be uploaded."""
        if mimetype is None:
            mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        self.files.append((fieldname, filename, mimetype, body))
        return
    
    def __str__(self):
        """Return a string representing the form data, including attached files."""
        # Build a list of lists, each containing "lines" of the
        # request.  Each part is separated by a boundary string.
        # Once the list is built, return a string where each
        # line is separated by '\r\n'.  
        parts = []
        part_boundary = '--' + self.boundary
        
        # Add the form fields
        parts.extend(
            [ part_boundary,
              'Content-Disposition: form-data; name="%s"' % name,
              '',
              value,
            ]
            for name, value in self.form_fields
            )
        
        # Add the files to upload
        parts.extend(
            [ part_boundary,
              'Content-Disposition: file; name="%s"; filename="%s"' % \
                 (field_name, filename),
              'Content-Type: %s' % content_type,
              '',
              body,
            ]
            for field_name, filename, content_type, body in self.files
            )
        
        # Flatten the list and add closing boundary marker,
        # then return CR+LF separated data
        flattened = list(itertools.chain(*parts))
        flattened.append('--' + self.boundary + '--')
        flattened.append('')
        return '\r\n'.join(flattened)
    

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
    
    def do_magic(self, magic):
        r = self.open_or_die("/devicemanagement/api/magic/do_magic?auth_token=%s" % self.auth_token, json.dumps(magic))
        return json.loads(r.read())
    
    def import_placeholder_devices(self, devices):
        csv = "DeviceName,SerialNumber,udid,IMEI,MEID\n%s\n" % "\n".join(devices)
        form_data = MultiPartForm()
        form_data.add_file("upload", "import.csv", csv, "text/csv")
        print form_data
        r = self.open_or_die("/devicemanagement/api/data_file/upload", str(form_data))
        response = json.loads(r.read())
        try:
            file_id = response["result"]["file"]["created"][0]["id"]
        except:
            raise PMError("CSV upload failed")
        response = self.do_magic({"file":{"import_placeholder_devices":[[file_id]]}})
        import pprint
        pprint.pprint(response)
    
    def add_placeholder_device(self, name, serial):
        response = self.do_magic({"device":{"create":[[{"SerialNumber":serial,"DeviceName":name}]]}})
        try:
            device_id = response["result"]["device"]["created"][0]["id"]
        except:
            raise PMError("Couldn't add device")
        return device_id
    
    def delete_device(self, device_id):
        response = self.do_magic({"device":{"destroy":[[device_id]]}})
        import pprint
        pprint.pprint(response)
    
    def add_device_to_group(self, group_id, device_id):
        response = self.do_magic({
            "device_group": {
                "add_device": [[group_id, {"id": [device_id]}]]
            }
        })
    
    def get_device_group_ids(self):
        response = self.do_magic({"device_group": {"find_all": [["GIMME"]]}})
        return response["remote"]["GIMME"][0][1:]
    
    def get_device_group_details(self, group_id):
        return self.do_magic({
            "device_group": {
                "get_details": [[None, {"ids": [group_id]}]]
            }
        })["result"]["device_group"]["retrieved"][0]
    

def main(argv):
    p = optparse.OptionParser()
    p.set_usage("""Usage: %prog [options] server username password""")
    p.add_option("-v", "--verbose", action="store_true",
                 help="Verbose output.")
    options, argv = p.parse_args(argv)
    if len(argv) != 4:
        print >>sys.stderr, p.get_usage()
        return 1
    
    server = argv[1]
    username = argv[2]
    password = argv[3]
    
    pm = ProfileManager(server)
    pm.authenticate(username, password)
    
    device_group_ids = pm.get_device_group_ids()
    groups_by_id = dict()
    groups_by_name = dict()
    for group_id in device_group_ids:
        group = pm.get_device_group_details(group_id)
        groups_by_id[group_id] = group
        groups_by_name[group["name"]] = group
    
    device_id = pm.add_placeholder_device("pmcli_test", "C080dea31")
    pm.add_device_to_group(groups_by_name["slask"]["id"], device_id)
    
    return 0
    

if __name__ == '__main__':
    sys.exit(main(sys.argv))
    

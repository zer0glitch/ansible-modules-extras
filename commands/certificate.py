#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Matt Martz <matt@sivel.net>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: certificate
short_description: Manages server and client certificates.  
description:
    - Creates public, private certificates in PEM and PKCS12 formats
author:
    - "Richard Clayton (@rclayton-the-terrible)"
    - "James Whetsell (@zer0glitch)"
version_added: 2.2
options:
  cadir:
    description:
      - The directory to store the certificate
    required: true
  certname:
    description:
      - The CN (common name) for the certificate
    required: true
  subj:
    description:
      - The full subject path for the certificate
    required: true
  p12password:
    description:
      - The password for the PKCS12 certificate
    required: true
  state:
    description:
      - To create or remove the CA. Present or absent: default is present.
    required: false
    default: present
    choices: [ "present", "absent" ]
  subjectAltNames:
    description:
      - Alternative names for the certificate.  Can be DNS, IP, etc.
    required: false
requirements: [ openssl ]
'''

RETURN = '''
output:
  path: location certificate created
'''


EXAMPLES = '''
- name: Create a Server Cert
  certificate: cadir="/etc/certs" certname="server.example.com" subj="/DC=com/DC=example/CN=server/" p12password="{{some_env_var}}"

- name: Create a Client Cert
  certificate: cadir="/etc/certs" certname="client.example.com" subj="/DC=com/DC=example/CN=client/" p12password="{{some_env_var}}" certtype="client"

- name: Remove a Server Cert
  certificate: cadir="/etc/certs" certname="server.example.com" subj="doesn't matter" p12password="blah!" state="absent"
'''

import os
from subprocess import call

import time


KEY_STRENGTH = 2048
DAYS_VALID  = 3653 # ~10 years
TMPL_GEN_PK =   "openssl genrsa -out {0}.key.pem {1}"
TMPL_GEN_REQ =  "openssl req -config {0}/openssl.cnf -new -key {1}.key.pem -out {1}.req.pem -outform PEM -subj \"{2}\" -nodes"

TMPL_SIGN_REQ = "openssl ca -config {0}/openssl.cnf -in {1}/{2}.req.pem -out {1}/{2}.cert.pem.pub  -batch -extensions {3}"

TMPL_PKCS12 =   "openssl pkcs12 -export -out {0}.keycert.p12 -name {0} -chain -in {0}.cert.pem.pub -inkey {0}.key.pem -passout file:{1} -CApath {2}"
TMPL_REVOKE = "openssl ca -config {0}/openssl.cnf -revoke {1} -keyfile {0}/private/cakey.pem -cert {0}/cacert.pem"
TMPL_GEN_CRL = "openssl ca -config {0}/openssl.cnf -gencrl -keyfile {0}/private/cakey.pem -cert {0}/cacert.pem -out crl.pem"
DEV_NULL = open('/dev/null', 'w')


OPENSSL_CNF = """
#
# OpenSSL example configuration file.
# This is mostly being used for generation of certificate requests.
#

# This definition stops the following lines choking if HOME isn't
# defined.
HOME      = .
RANDFILE    = $ENV::HOME/.rnd

# Extra OBJECT IDENTIFIER info:
#oid_file   = $ENV::HOME/.oid


[ ca ]
default_ca = ca

[ ca ]
dir = {0}
certificate = $dir/cacert.pem
database = $dir/index.txt
new_certs_dir = $dir/certs
private_key = $dir/private/cakey.pem
serial = $dir/serial

default_crl_days = 7
default_days = 365
default_md = sha1

policy = policy_match
x509_extensions = certificate_extensions


input_password = test
output_password = test

# Comment out the following two lines for the "traditional"
# (and highly broken) format.
name_opt  = ca_default    # Subject Name options
cert_opt  = ca_default    # Certificate field options

# Extension copying option: use with caution.
# copy_extensions = copy

# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
# so this is commented out by default to leave a V1 CRL.
# crl_extensions  = crl_ext

default_days  = 365     # how long to certify for
default_crl_days= 30      # how long before next CRL
default_md  = sha256      # which md to use.
preserve  = no      # keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy    = policy_anything

#policy = policy_match

# For the CA policy
[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ certificate_extensions ]
basicConstraints = CA:false

####################################################################
[ req ]
dir = {0}
default_bits    = 2048
default_key = $dir/private/cakey.pem
x509_extensions = v3_ca # The extentions to add to the self signed cert
distinguished_name      = req_distinguished_name
attributes              = req_attributes

# Passwords for private keys if not present they will be prompted for
# input_password = secret
# output_password = secret

# This sets a mask for permitted string types. There are several options. 
# default: PrintableString, T61String, BMPString.
# pkix   : PrintableString, BMPString.
# utf8only: only UTF8Strings.
# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
# MASK:XXXX a literal mask value.
# WARNING: current versions of Netscape crash on BMPStrings or UTF8Strings
# so use this option with caution!
string_mask = nombstr

# req_extensions = v3_req # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName     = Country Name (2 letter code)
countryName_default   = US
countryName_min     = 2
countryName_max     = 2

#stateOrProvinceName    = State or Province Name (full name)
#stateOrProvinceName_default  = Berkshire

#localityName     = Locality Name (eg, city)
#localityName_default   = Newbury

0.organizationName    = Organization Name (eg, company)
0.organizationName_default  = Tactical Cloud Reference Implmentation

# we can do this but it is not needed normally :-)
#1.organizationName   = Second Organization Name (eg, company)
#1.organizationName_default = ONR Test

organizationalUnitName    = Organizational Unit Name (eg, section)
organizationalUnitName_default  = Hosts

commonName      = Common Name (eg, your name or your server\'s hostname)
commonName_max      = 64
commonName_default    = {1}

#emailAddress     = Email Address
#emailAddress_max   = 64

# SET-ex3     = SET extension number 3

[ req_attributes ]
#challengePassword    = A challenge password
#challengePassword_min    = 4
#challengePassword_max    = 20
#challengePassword_default  = password

unstructuredName    = FakeCert

[ server_ca_extensions ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
#nsCertType     = server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email
# nsCertType = client

# and for everything including object signing:
nsCertType = server, client, email, objsign

# This is typical in keyUsage for a client certificate.
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
#nsComment      = "Test Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

subjectAltName = {2}

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]


# Extensions for a typical CA


# PKIX recommendation.

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer:always

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.
basicConstraints = CA:true

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always,issuer:always
"""

class Certificate:

    def __init__(self, cadir, certname, subj, p12password, isServerCert, subjectAltNames):
        self.cadir = os.path.realpath(self.normalize_directory_path(cadir))
        self.certname = certname
        self.subj = subj
        self.p12password = p12password
        self.isServerCert = isServerCert
        self.subjectAltNames = subjectAltNames

    def normalize_directory_path(self, path):
        if path.endswith(os.sep):
            return path[:-1]
        else:
            return path

    def execute_command(self, cmd):
        call(cmd, shell=True, stdout=DEV_NULL, stderr=DEV_NULL)

    def read_file(self, filename):
        with open(filename, "r") as f:
            return f.read()

    def ensure_directory_exists(self, dir):
        if not os.path.exists(dir):
            os.makedirs(dir)

    def generate_private_key(self):
        cmd = TMPL_GEN_PK.format(self.get_target_path() + "/" + self.certname, KEY_STRENGTH)
        self.execute_command(cmd)

    def generate_certificate_request(self):
        cmd = TMPL_GEN_REQ.format(self.get_openssl_cnf(), self.get_target_path() + "/" + self.certname, self.subj)
        self.execute_command(cmd)
  
    def sign_certificate_request(self, curdir):
        os.chdir("..")
        cmd = ""
        ext = "server_ca_extensions -policy policy_anything " if self.isServerCert else "usr_cert -policy policy_anything"
        cmd = TMPL_SIGN_REQ.format(self.get_openssl_cnf(), self.get_target_path(), self.certname, ext)
        self.execute_command(cmd)
        os.chdir(curdir)

    def create_key_cert_PEM(self):
        keyPem = self.read_file(self.get_target_path() + "/" + self.certname + ".key.pem")
        cerPem = self.read_file(self.get_target_path() + "/" + self.certname + ".cert.pem.pub")
        with open(self.get_target_path() + "/" + self.certname + ".keycert.pem", "w") as kcFile:
            kcFile.write(keyPem)
            kcFile.write("\n")
            kcFile.write(cerPem)

    def export_key_as_PKCS12(self):
        passwordFile = self.get_target_path() + "/" +  self.certname + ".password"
        with open(passwordFile, "w") as f:
            f.write(self.p12password)
        cmd = TMPL_PKCS12.format(self.certname, passwordFile, self.cadir)
        self.execute_command(cmd)
        os.remove(passwordFile)

    def get_openssl_cnf(self):
        return self.cadir + "/server/" + self.certname  if self.isServerCert else self.cadir

    def get_target_path(self):
        return self.cadir + "/server/" + self.certname  if self.isServerCert else self.cadir + "/client"
        
    def validate_config(self):
        if not os.path.exists(self.cadir):
            return dict(success=False, msg="CA directory does not exist.")
        elif not os.path.exists(self.cadir + os.sep + "cacert.pem"):
            return dict(success=False, msg="CA directory does not contain a valid CA configuration.")
        elif not "CN=" in self.subj:
            return dict(success=False, msg="Common Name (CN) not found in subject string.")
        else:
            return dict(success=True)

    def validate_removal_config(self):
        if not os.path.exists(self.cadir):
            return dict(success=False, msg="CA directory does not exist.")
        else:
            return dict(success=True)

    def create_server_cnf(self, target_path):
        fileOpensslCnf = target_path + "/openssl" + ".cnf"
        if not os.path.exists(fileOpensslCnf):
            opensslCnf = open(fileOpensslCnf, "w")
            alt_names = self.subjectAltNames
            opensslCnf.write(OPENSSL_CNF.format(self.cadir, self.certname, alt_names))
            opensslCnf.close()
            changed = True        


    def create_certificate(self):

        CURDIR = os.getcwd()

        os.chdir(self.cadir)

        changed = False
        changes = []

        target_path = self.get_target_path()

        self.ensure_directory_exists(target_path)

        os.chdir(target_path)


        if not os.path.exists(target_path + "/openssl" + ".cnf"): #and self.isServerCert:
            self.create_server_cnf(target_path)
            changes.append("Created server cnf for {0}.".format(self.certname))
            changed = True

        if not os.path.exists(self.certname + ".key.pem"):
            self.generate_private_key()
            changes.append("Created private key for {0}.".format(self.certname))
            changed = True

        if not os.path.exists(self.certname + ".req.pem"):
            self.generate_certificate_request()
            changes.append("Created certificate request for {0}".format(self.certname))
            changed = True

        if not os.path.exists(self.certname + ".cert.pem.pub"):
            self.sign_certificate_request(target_path)
            changes.append("Signed certificate for {0}".format(self.certname))
            changed = True

        if not os.path.exists(self.certname + ".keycert.pem"):
            self.create_key_cert_PEM()
            changes.append("Created key-cert PEM file for {0}".format(self.certname))

        if not os.path.exists(self.certname + ".keycert.p12"):
            self.export_key_as_PKCS12()
            changes.append("Created PKCS12 version of the Private Key/Certificate Pair for {0}".format(self.certname))
            changed = True

        os.chdir(CURDIR)

        return dict(success=True, changed=changed, changes=changes)

    def revoke_certificate(self):

        CURDIR = os.getcwd()

        os.chdir("..")

        cmd = TMPL_REVOKE.format(self.cadir, CURDIR + os.sep + self.certname + ".cert.pem.pub")
        self.execute_command(cmd)

        cmd2 = TMPL_GEN_CRL.format(self.cadir)
        self.execute_command(cmd2)

        os.chdir(CURDIR)


    def remove_certificate(self):

        CURDIR = os.getcwd()

        changed = False
        changes = []

        target_path = self.get_target_path()

        if not os.path.exists(target_path):
            return dict(success=True, changed=changed, changes=changes, msg="{0} does not exist, therefore cert doesn't exist.".format(target_path))

        os.chdir(target_path)

        if os.path.exists(self.certname + ".key.pem"):
            os.remove(self.certname + ".key.pem")
            changes.append("Removed private key for {0}.".format(self.certname))
            changed = True

        if os.path.exists(self.certname + ".req.pem"):
            os.remove(self.certname + ".req.pem")
            changes.append("Removed certificate request for {0}".format(self.certname))
            changed = True

        if os.path.exists(self.certname + ".cert.pem.pub"):
            self.revoke_certificate()
            os.remove(self.certname + ".cert.pem.pub")
            changes.append("Removed certificate for {0}".format(self.certname))
            changed = True

        if os.path.exists(self.certname + ".keycert.pem"):
            os.remove(self.certname + ".keycert.pem")
            changes.append("Removed key-cert PEM file for {0}".format(self.certname))

        if os.path.exists(self.certname + ".keycert.p12"):
            os.remove(self.certname + ".keycert.p12")
            changes.append("Removed PKCS12 version of the Private Key/Certificate Pair for {0}".format(self.certname))
            changed = True

        os.chdir(CURDIR)

        return dict(success=True, changed=changed, changes=changes)





def main():

    BASE_MODULE_ARGS = dict(
        cadir = dict(default="/etc/certs"),
        certname = dict(required=True),
        subj = dict(default="/DC=com/DC=example/CN=CA/"),
        p12password = dict(required=True),
        certtype = dict(default="server", choices=["server", "client"]),
        state = dict(default="present", choices=["present", "absent"]),
        subjectAltNames = dict(required=False)
    )

    module = AnsibleModule(
        argument_spec= BASE_MODULE_ARGS,
        supports_check_mode=True
    )

    isServerCert = True

    if module.params["certtype"] == "client":
        isServerCert = False

    # cadir, certname, subj, p12password, isServerCert
    cert = Certificate(
        module.params["cadir"],
        module.params["certname"],
        module.params["subj"],
        module.params["p12password"],
        isServerCert,
        module.params["subjectAltNames"]
    )

    isValid = cert.validate_config()

    if isValid["success"]:
        if module.params["state"] == "present":
            isValid = cert.create_certificate()
        else:
            isValid = cert.remove_certificate()

    if not isValid["success"]:
        module.fail_json(msg=isValid["msg"])
    else:
        module.exit_json(**isValid)

# import module snippets
from ansible.module_utils.basic import *

main()

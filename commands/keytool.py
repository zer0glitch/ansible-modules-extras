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
module: keytool
short_description: Manages keystores and truststores for java
description:
    - Creates and Manages java keystores and truststores
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
  store_password:
    description:
      - The password for the store
    required: true
  host_to_trust:
    description:
      - A list of hsots to add to the truststore
    required: false
  state:
    description:
      - To create or remove the CA. Present or absent: default is present.
    required: false
    default: present
    choices: [ "present", "absent" ]
  certtype:
    description:
      - The certificate type.  Values: keystore or truststore
    required: false
    default: truststore
    choices: [ "keystore", "truststore" ]
  src_password:
    description:
      - Source password for the PKCS12 certificate that is being imported
    required: false
requirements: [ keytool ]
'''

RETURN = '''
output:
  path: location of store created
'''


EXAMPLES = '''
- name: Create a java server trustore and trust the server hosts
  keytool: cadir="/etc/certs" certname="host1.example.com" store_password='changeit' hosts_to_trust="host1.example.com"

  - name: Create a java server keystore 
    keytool: cadir="/etc/certs" certname="host1.example.com" store_password='changeit'  certtype="keystore" src_password='changeit'
'''



from subprocess import call
import os

TMPL_GEN_TS = "keytool -import -noprompt -alias {0} -file {1} -keystore {2} -storepass '{3}'"
TMPL_GEN_KS = "keytool -importkeystore -noprompt -alias {0} -srckeystore {1} -destkeystore {2}  -srcstoretype PKCS12   -deststorepass '{3}' -destkeypass '{3}' -srcstorepass '{4}'"

DEV_NULL = open('/dev/null', 'w')

class Keytool:


    def __init__(self, cadir, certname, store_password, hosts_to_trust, certtype, src_password):

        self.cadir = os.path.realpath(cadir)
        self.certname = certname
        self.certtype = certtype
        self.store_password = store_password
        self.src_password = src_password
        self.hosts_to_trust = hosts_to_trust

    def execute_command(self, cmd):
        call(cmd, shell=True, stdout=DEV_NULL, stderr=DEV_NULL)

    def validate(self):

        if not os.path.exists(self.cadir):
            return dict(success=False, msg="CA directory '{0}' does not exist.".format(self.cadir))
        elif self.certtype == 'truststore' and len(self.hosts_to_trust) == 0:
            return dict(success=False, msg="No hosts specified for the truststore.")
        else:
            return dict(success=True)

    def ensure_directory_exists(self, dir):
        if not os.path.exists(dir):
            os.mkdir(dir)

    def get_truststore_path(self, certtype):
        if certtype == "keystore":
          return self.cadir + "/keystores" + os.sep + self.certname + ".keystore.jks"
        else:
          return "truststores" + os.sep + self.certname + ".trust.jks"

    def get_storepass_path(self):
        return self.certname + ".storepass"

    def resolve_certificate(self, host):
        server = ""
        client = ""
        if self.certtype == "keystore":
          server = self.cadir + "/server/{0}/{0}.keycert.p12".format(host)
          client = self.cadir + "/client/{0}.keycert.p12".format(host)
        else:
          server = self.cadir + "/server/{0}/{0}.cert.pem.pub".format(host)
          client = self.cadir + "/client/{0}.keycert.pem".format(host)
        if os.path.exists(server):
            return server
        elif os.path.exists(client):
            return client
        else:
            return None

    def build_trust_store(self):

        changed = False
        success = True
        errors = []
        changes = []

        CURDIR = os.getcwd()

        os.chdir(self.cadir)

        if self.certtype == "truststore":
          self.ensure_directory_exists("truststores")
        else:
          self.ensure_directory_exists("keystores")

        truststore_path = self.get_truststore_path(self.certtype)
        storepass_path = self.get_storepass_path()

        if not os.path.exists(truststore_path):

            # Write the password out to file.
            with open(storepass_path, "w") as storepass:
                storepass.write(self.store_password)

            try:

                if self.certtype == "truststore":
                  cmd = TMPL_GEN_TS.format("CA", self.cadir + "/cacert.pem", self.cadir + "/" + truststore_path, self.store_password)
                  self.execute_command(cmd)
                  changed = True
                  changes.append("Added the CA Certificate to the truststore: " + cmd)

                if self.certtype == "keystore":
                    hostcert = self.resolve_certificate(self.certname)
                    cmd = TMPL_GEN_KS.format(self.certname, hostcert, truststore_path, self.store_password, self.src_password)
                    self.execute_command(cmd)
                    changes.append(cmd)
                    os.chdir(CURDIR)

                    return dict(success=success, changed=changed, changes=changes, path=truststore_path, errors=errors, msg=", ".join(errors))

                for host in self.hosts_to_trust:

                    hostcert = self.resolve_certificate(host)

                    cmd = ""
                    if not hostcert is None:
                        cmd = TMPL_GEN_TS.format(host, hostcert, truststore_path, self.store_password)

                        changes.append("Executing: '{0}'".format(cmd))
                        self.execute_command(cmd)
                        changed = True
                        changes.append("Added '{0}' to the truststore.".format(host))
                        changes.append(cmd)
                    else:
                        success=False
                        errors.append("Could not find cert for host: {0}".format(hostcert))

            except Exception as e:
                success = False
                errors.append(e.message)

            finally:
                # Remove the password
                if os.path.exists(storepass_path):
                    os.remove(storepass_path)

        if success == False:
            os.remove(truststore_path)

        os.chdir(CURDIR)

        return dict(success=success, changed=changed, changes=changes, path=truststore_path, errors=errors, msg=", ".join(errors))


    def remove_trust_store(self):

        changed = False
        changes = []

        CURDIR = os.getcwd()

        os.chdir(self.cadir)

        truststore_path = self.get_truststore_path(self.certtype)

        if os.path.exists(truststore_path):
            os.remove(truststore_path)
            changed=True
            changes.append("Successfully removed truststore.")

        os.chdir(CURDIR)

        return dict(success=True, changed=changed, changes=changes, msg="")







def main():

    BASE_MODULE_ARGS = dict(
        cadir = dict(default="/etc/certs"),
        certname = dict(required=True),
        store_password = dict(required=True),
        hosts_to_trust = dict(required=False, type="list"),
        state = dict(default="present", choices=["present", "absent"]),
        certtype = dict(required=False, default="truststore", choices=["truststore","keystore"]),
        src_password = dict(required=False)
    )

    module = AnsibleModule(
        argument_spec= BASE_MODULE_ARGS,
        supports_check_mode=True
    )

    keytool = Keytool(
        module.params["cadir"],
        module.params["certname"],
        module.params["store_password"],
        module.params["hosts_to_trust"],
        module.params["certtype"],
        module.params["src_password"],
    )

    isValid = keytool.validate()

    if isValid["success"]:
        if module.params["state"] == "present":
            isValid = keytool.build_trust_store()
        else:
            isValid = keytool.remove_trust_store()

    if not isValid["success"]:
        module.fail_json(msg=isValid["msg"])
    else:
        module.exit_json(**isValid)

# import module snippets
from ansible.module_utils.basic import *

main()
